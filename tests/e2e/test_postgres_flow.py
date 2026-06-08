"""End-to-end: install Postgres from the marketplace, mask fields, add a guardrail, verify blocking.

Mirrors the manual flow the dev team walks through after every release:

    1. Install Postgres from the marketplace using OM_E2E_PG_URI for DATABASE_URI.
    2. Hide the ``list_objects`` tool from agents.
    3. Open ``execute_sql``.
    4. Run ``select * from users;``.
    5. Click ``Mask`` next to an ``email`` leaf → the inline rule editor opens → save it.
    6. Manually add a path rule for ``phone_number``.
    7. Re-call the tool and confirm both fields rendered as aliases.
    8. Add a ``contains "drOP"`` guardrail on the ``sql`` argument.
    9. Try ``drop table something;`` and confirm the call is blocked.

Run with:
    OM_E2E_PG_URI=postgresql://... uv run --group e2e pytest tests/e2e -m e2e -v

The Postgres URI must be reachable from inside the postgres-mcp container the
marketplace install spawns (so on macOS, use ``host.containers.internal`` or
``host.docker.internal`` rather than ``localhost``).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


# Catalog handle for the marketplace's PostgreSQL entry. The display name in
# the catalog is "PostgreSQL"; the install handle (used in URLs) is "postgres".
PG_HANDLE = "postgres"


@pytest.fixture
def page(openmaskit_server: str, page: Page) -> Page:
    """Pre-navigate to the dashboard and dismiss the welcome modal once per test."""
    page.set_default_timeout(15_000)
    page.goto(openmaskit_server)
    skip = page.get_by_role("button", name="Skip for now")
    if skip.is_visible():
        skip.click()
    return page


def _install_postgres(page: Page, pg_uri: str) -> None:
    page.goto(f"{page.url.rstrip('/')}/marketplace")
    page.get_by_role("textbox", name=re.compile(r"Search servers", re.I)).fill("postgres")
    page.get_by_role("button", name="Install PostgreSQL").click()
    page.get_by_role("textbox", name="Database URI").fill(pg_uri)
    page.get_by_role("button", name="Install", exact=True).click()
    expect(page.get_by_text("Connected", exact=True)).to_be_visible(timeout=60_000)


def _wait_for_tools_loaded(page: Page) -> None:
    """The proxy starts the upstream container lazily; tool schemas appear within a few seconds."""
    page.goto(f"http://127.0.0.1:19473/targets/{PG_HANDLE}/tools")
    expect(page.get_by_role("heading", name="execute_sql")).to_be_visible(timeout=30_000)
    expect(page.get_by_role("heading", name="list_objects")).to_be_visible()


def _tool_card(page: Page, tool_name: str):
    """The card wrapping a tool's link + hide button on the tools list page."""
    return page.locator(".tool-card-wrapper").filter(
        has=page.locator(f'a[href$="/tools/{tool_name}"]')
    )


def _tree_leaf_with_key(page: Page, key: str):
    """Tree leaves are ``.tree-node > .tree-leaf > .tree-key``. Returns the leaf span."""
    return page.locator(".tree-node").filter(
        has=page.locator(".tree-key", has_text=f"{key}:")
    )


def test_postgres_install_mask_and_guardrail(page: Page, pg_uri: str) -> None:
    # === Step 1: install Postgres from the marketplace ===
    _install_postgres(page, pg_uri)

    # === Step 2: hide list_objects ===
    _wait_for_tools_loaded(page)
    list_objects_card = _tool_card(page, "list_objects")
    list_objects_card.locator(".tool-hide-btn").click()
    expect(list_objects_card).to_have_class(re.compile(r"\btool-card-hidden\b"))

    # === Step 3+4: open execute_sql, run a select ===
    page.goto(f"http://127.0.0.1:19473/targets/{PG_HANDLE}/tools/execute_sql")
    sql_input = page.get_by_role("textbox", name="sql string")
    call_button = page.get_by_role("button", name="Call", exact=True)
    sql_input.fill("select * from users;")
    call_button.click()

    # Wait for at least one tree leaf to render.
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=30_000)

    # === Step 5: click Mask on the email leaf, save the draft rule ===
    email_leaf = _tree_leaf_with_key(page, "email").first
    email_leaf.locator(".tree-action").click()
    # Both email leaves in the tree should highlight as pending-mask once the
    # draft rule (path = "email") is staged.
    expect(page.locator(".tree-node-pending-mask")).to_have_count(2)
    # Inline rule editor opens in the Active rules table.
    page.get_by_role("button", name="Save", exact=True).click()
    active_rules = page.locator(".panel", has=page.get_by_role("heading", name="Masking", exact=False)).locator("table")
    expect(active_rules.locator("code", has_text="email")).to_be_visible()

    # === Step 6: manually add a path rule for phone_number ===
    page.get_by_text("Add a field path manually", exact=True).click()
    page.get_by_role("textbox", name="Field Path").fill("phone_number")
    page.get_by_role("button", name="Add Rule", exact=True).click()
    expect(active_rules.locator("code", has_text="phone_number")).to_be_visible()

    # === Step 7: re-call and verify both fields are aliased ===
    call_button.click()
    # New tree should render with no email/phone literal values visible as leaves.
    # We assert the aliases appear and the originals only appear in tooltips.
    aliased_email = page.locator(".tree-value", has_text=re.compile(r"_masked_email_\d+"))
    expect(aliased_email.first).to_be_visible(timeout=30_000)
    aliased_phone = page.locator(".tree-value", has_text=re.compile(r"_masked_phone_number_\d+"))
    expect(aliased_phone.first).to_be_visible()
    # Sanity: the original cleartext should never be a tree-value (it lives in .masked-tooltip).
    raw_email = page.locator(".tree-value", has_text=re.compile(r"@"))
    expect(raw_email).to_have_count(0)

    # === Step 8: add a guardrail: sql / contains / drOP ===
    # Scope to the Argument Guardrails panel — "Argument" and "Pattern" labels
    # also appear in the Injections / Masking sections.
    guardrails_section = page.locator(".panel").filter(
        has=page.get_by_role("heading", name=re.compile(r"^Argument Guardrails"))
    )
    # The form has two selects (Argument, Match) and two textboxes (Pattern, Message)
    # in document order — pick by position so we don't depend on label association.
    guardrails_section.locator("select").nth(0).select_option("sql")
    guardrails_section.locator('input[type="text"]').nth(0).fill("drOP")
    guardrails_section.get_by_role("button", name="Add Guardrail", exact=True).click()
    # Row appears in the guardrails table.
    expect(guardrails_section.locator("code", has_text="drOP")).to_be_visible()

    # === Step 9: try a DROP and confirm it's blocked ===
    sql_input.fill("drop table something;")
    call_button.click()
    expect(page.get_by_text(re.compile(r"Blocked by guardrail", re.I))).to_be_visible(timeout=10_000)
