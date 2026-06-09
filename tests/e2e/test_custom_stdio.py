"""End-to-end: full custom-stdio target lifecycle through the dashboard.

Exercises the Add Server modal, tool discovery, hover-to-mask, deactivate,
activate, delete — all against the stub MCP server in ``fixtures/`` so the
test runs with no external network or container dependencies.
"""

from __future__ import annotations

import re
import sys

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import E2E_BASE_URL, STUB_SERVER_PATH

pytestmark = pytest.mark.e2e


TARGET_ID = "stub"


def _add_custom_stdio_via_modal(page: Page, name: str, command: str, args: str) -> None:
    # On an empty dashboard there are TWO "Add Server" buttons (header + empty-state card).
    # Click the header one specifically.
    page.locator(".btn-add-target").click()
    modal = page.locator(".modal-target")
    modal.get_by_role("textbox", name="Name").fill(name)
    # stdio is the default — click anyway in case a prior test toggled it.
    modal.get_by_role("button", name="stdio", exact=True).click()
    modal.get_by_role("textbox", name="Command").fill(command)
    modal.get_by_role("textbox", name=re.compile(r"^Arguments")).fill(args)
    modal.get_by_role("button", name="Connect", exact=True).click()


def _target_card(page: Page, target_id: str):
    return page.locator(".tgt-card").filter(
        has=page.locator(f'a[href$="/targets/{target_id}/tools"]')
    )


def _inactive_target_card(page: Page, target_id: str):
    """Cards in the Inactive Servers section have no link to /tools."""
    return page.locator(".tgt-card-inactive").filter(
        has=page.locator(".tgt-card-name", has_text=target_id)
    )


def test_custom_stdio_full_lifecycle(dashboard_page: Page) -> None:
    page = dashboard_page

    # === Add the stub via the modal ===
    _add_custom_stdio_via_modal(
        page,
        name=TARGET_ID,
        command=sys.executable,
        args=str(STUB_SERVER_PATH),
    )
    # Card appears in Active Servers; wait for tool count to settle.
    active_card = _target_card(page, TARGET_ID)
    expect(active_card).to_be_visible(timeout=20_000)
    expect(active_card).to_contain_text("2 tools", timeout=20_000)

    # === Run lookup_user and mask the email field ===
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools/lookup_user")
    name_input = page.get_by_role("textbox", name=re.compile(r"^name "))
    name_input.fill("alice")
    call_button = page.get_by_role("button", name="Call", exact=True)
    call_button.click()
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)
    # Sanity: original email visible before any rule.
    expect(page.locator(".tree-value", has_text="alice@example.com")).to_be_visible()

    # Mask via hover-to-Mask on the email leaf. The mapper is created in one
    # shot — no draft / confirm step.
    email_leaf = page.locator(".tree-node").filter(
        has=page.locator(".tree-key", has_text="email:")
    ).first
    email_leaf.locator(".tree-action").click()

    # Re-call and verify the email is aliased.
    call_button.click()
    aliased_email = page.locator(".tree-value", has_text=re.compile(r"_masked_email_\d+"))
    expect(aliased_email.first).to_be_visible(timeout=15_000)
    # Original should no longer be a tree value (lives only in the tooltip).
    expect(page.locator(".tree-value", has_text="alice@example.com")).to_have_count(0)

    # === Hide the echo tool ===
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools")
    echo_card = page.locator(".tool-card-wrapper").filter(
        has=page.locator('a[href$="/tools/echo"]')
    )
    echo_card.locator(".tool-hide-btn").click()
    expect(echo_card).to_have_class(re.compile(r"\btool-card-hidden\b"))

    # Deactivate + Delete both use native confirm() dialogs.
    page.on("dialog", lambda d: d.accept())

    # === Deactivate from the active card ===
    page.goto(E2E_BASE_URL)
    active_card = _target_card(page, TARGET_ID)
    active_card.get_by_role("button", name=re.compile(r"^Deactivate")).click()
    # Card moves to the Inactive Servers section.
    inactive_card = _inactive_target_card(page, TARGET_ID)
    expect(inactive_card).to_be_visible(timeout=15_000)

    # === Activate from the inactive card ===
    inactive_card.get_by_role("button", name=re.compile(r"^Activate")).click()
    active_card = _target_card(page, TARGET_ID)
    expect(active_card).to_be_visible(timeout=15_000)
    # The hidden-tool state should survive — query the API rather than re-navigate.
    r = httpx.get(f"{E2E_BASE_URL}/api/targets/{TARGET_ID}/tools?include_hidden=1", timeout=5.0)
    assert r.status_code == 200
    assert "echo" in r.json().get("hidden_tools", [])

    # === Delete the target ===
    active_card.get_by_role("button", name=re.compile(r"^Delete")).click()
    expect(active_card).to_have_count(0, timeout=15_000)
    # Backend confirms the row is gone.
    r = httpx.get(f"{E2E_BASE_URL}/api/targets", timeout=5.0)
    assert all(t["name"] != TARGET_ID for t in r.json()["targets"])
