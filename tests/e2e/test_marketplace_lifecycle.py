"""End-to-end: marketplace server lifecycle + edit-gate regression tests.

Covers behaviours that recently broke or were intentionally tightened:

- Delete from the Inactive Servers section (regression for the "marketplace
  server cannot be deleted" bug fixed by routing the FE through the new
  ``/api/marketplace/{id}/delete`` endpoint based on ``target.source``).
- Active marketplace cards have NO Edit button, and the legacy
  ``PUT /api/targets/custom/{id}/update`` endpoint returns 403 when pointed
  at a marketplace-source row (defense in depth — gate is the backend,
  hiding the button is UX courtesy).
- Hidden-tool state and masking rules survive deactivate → activate.

All three tests install Postgres from the catalog, so they require
``OM_E2E_PG_URI`` and a reachable container runtime.
"""

from __future__ import annotations

import re

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import E2E_BASE_URL, api_client

pytestmark = pytest.mark.e2e


PG_HANDLE = "postgres"


def _install_postgres(page: Page, pg_uri: str) -> None:
    """Drive the marketplace install modal for Postgres."""
    page.goto(f"{E2E_BASE_URL}/marketplace")
    page.get_by_role("textbox", name=re.compile(r"Search servers", re.I)).fill("postgres")
    page.get_by_role("button", name="Install PostgreSQL").click()
    page.get_by_role("textbox", name="Database URI").fill(pg_uri)
    page.get_by_role("button", name="Install", exact=True).click()
    expect(page.get_by_text("Connected", exact=True)).to_be_visible(timeout=60_000)


def _target_card(page: Page, target_id: str):
    return page.locator(".tgt-card").filter(
        has=page.locator(f'a[href$="/targets/{target_id}/tools"]')
    )


def _inactive_card(page: Page, display_name: str):
    return page.locator(".tgt-card-inactive").filter(
        has=page.locator(".tgt-card-name", has_text=display_name)
    )


def test_marketplace_delete_from_inactive_card(dashboard_page: Page, pg_uri: str) -> None:
    """Regression: deleting an inactive marketplace server actually deletes it.

    Before the fix, clicking Delete on an inactive marketplace card routed
    to the custom-target endpoint, which 403'd ("This server was installed
    from the marketplace; manage it from the Marketplace page.").
    """
    page = dashboard_page
    _install_postgres(page, pg_uri)

    # Accept the browser confirm() dialogs for deactivate + delete.
    page.on("dialog", lambda d: d.accept())

    # Deactivate → card moves to Inactive Servers section.
    page.goto(E2E_BASE_URL)
    active_card = _target_card(page, PG_HANDLE)
    active_card.get_by_role("button", name=re.compile(r"^Deactivate")).click()
    inactive_card = _inactive_card(page, "PostgreSQL")
    expect(inactive_card).to_be_visible(timeout=15_000)

    # Delete from the inactive card. Before the fix this 403'd.
    inactive_card.get_by_role("button", name=re.compile(r"^Delete")).click()
    expect(inactive_card).to_have_count(0, timeout=15_000)

    # Backend agrees the row is gone.
    targets = httpx.get(f"{E2E_BASE_URL}/api/targets", timeout=5.0).json()["targets"]
    assert all(t["name"] != PG_HANDLE for t in targets)


def test_marketplace_edit_button_absent_and_backend_gates_update(
    dashboard_page: Page, pg_uri: str
) -> None:
    """Edit is hidden in the FE AND the backend rejects the custom-target update.

    The FE-side hiding is UX courtesy; the backend gate in ``_resolve_custom_target``
    is the authoritative boundary. Verifying both ensures a regression in
    either layer is caught.
    """
    page = dashboard_page
    _install_postgres(page, pg_uri)

    # FE: no Edit button on the active marketplace card (only Connect / Deactivate / Delete).
    page.goto(E2E_BASE_URL)
    active_card = _target_card(page, PG_HANDLE)
    expect(active_card).to_be_visible()
    expect(active_card.get_by_role("button", name=re.compile(r"^Edit"))).to_have_count(0)

    # Backend: the legacy custom-target update endpoint 403s on a marketplace row.
    with api_client() as client:
        r = client.post(
            f"/api/targets/custom/{PG_HANDLE}/update",
            json={"name": PG_HANDLE, "transport": "stdio", "command": "evil"},
        )
    assert r.status_code == 403
    body = r.json()
    assert "marketplace" in body.get("error", "").lower()


def test_hidden_tool_and_rules_survive_deactivate_activate(
    dashboard_page: Page, pg_uri: str
) -> None:
    """Hide a tool + add a rule, deactivate, activate, confirm both persist.

    Specifically guards the bug found while writing this suite where
    ``manager.add_target`` was constructing the engine with an empty rules
    list — masking rules silently vanished on reactivation.
    """
    page = dashboard_page
    _install_postgres(page, pg_uri)

    # Wait for tool list, hide list_objects.
    page.goto(f"{E2E_BASE_URL}/targets/{PG_HANDLE}/tools")
    expect(page.get_by_role("heading", name="execute_sql")).to_be_visible(timeout=30_000)
    list_objects_card = page.locator(".tool-card-wrapper").filter(
        has=page.locator('a[href$="/tools/list_objects"]')
    )
    list_objects_card.locator(".tool-hide-btn").click()
    expect(list_objects_card).to_have_class(re.compile(r"\btool-card-hidden\b"))

    # Add a path mask rule on `email` via the API (faster than the UI).
    with api_client() as client:
        r = client.post(
            f"/api/targets/{PG_HANDLE}/rules/create",
            json={
                "tool_name": "execute_sql",
                "field_path": "email",
                "alias_prefix": "email",
                "action": "mask",
            },
        )
        r.raise_for_status()

    # Deactivate + activate via the marketplace API.
    page.on("dialog", lambda d: d.accept())
    with api_client() as client:
        r = client.post("/api/marketplace/deactivate", json={"server_id": PG_HANDLE})
        r.raise_for_status()
        r = client.post("/api/marketplace/activate", json={"server_id": PG_HANDLE})
        r.raise_for_status()

    # Wait for the upstream container to come back online.
    for _ in range(60):
        tools = httpx.get(f"{E2E_BASE_URL}/api/targets/{PG_HANDLE}/tools", timeout=5.0)
        if tools.status_code == 200 and tools.json().get("tools"):
            break
    else:
        pytest.fail("postgres did not re-initialize after activate")

    # Hidden state: list_objects still in hidden_tools.
    r = httpx.get(
        f"{E2E_BASE_URL}/api/targets/{PG_HANDLE}/tools?include_hidden=1", timeout=5.0
    )
    assert "list_objects" in r.json().get("hidden_tools", [])

    # Rule still applied: a fresh execute_sql call aliases the email field.
    page.goto(f"{E2E_BASE_URL}/targets/{PG_HANDLE}/tools/execute_sql")
    page.get_by_role("textbox", name="sql string").fill("select * from users;")
    page.get_by_role("button", name="Call", exact=True).click()
    expect(
        page.locator(".tree-value", has_text=re.compile(r"email_\d+")).first
    ).to_be_visible(timeout=30_000)
