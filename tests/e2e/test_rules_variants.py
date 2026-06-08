"""End-to-end: rule action=strip, argument injections, guardrail match variants.

Each test installs the stub MCP server via the JSON API (skipping the Add
Server modal — which the lifecycle test already covers) and then exercises
the feature under test through the dashboard.
"""

from __future__ import annotations

import re

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import E2E_BASE_URL, api_client, install_stub_via_api

pytestmark = pytest.mark.e2e


TARGET_ID = "stub"


@pytest.fixture
def stub(openmaskit_server: str) -> str:
    install_stub_via_api(TARGET_ID)
    return TARGET_ID


def _call_lookup_user(page: Page, name: str = "alice") -> None:
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools/lookup_user")
    page.get_by_role("textbox", name=re.compile(r"^name ")).fill(name)
    page.get_by_role("button", name="Call", exact=True).click()
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)


def _open_manual_rule_entry(page: Page) -> None:
    page.get_by_text("Add a field path manually", exact=True).click()


def test_strip_rule_removes_field_entirely(dashboard_page: Page, stub: str) -> None:
    """``action=strip`` removes the field from the response (no alias)."""
    page = dashboard_page
    _call_lookup_user(page)
    # Sanity: host field is present before the rule.
    expect(page.locator(".tree-key", has_text="host:").first).to_be_visible()

    _open_manual_rule_entry(page)
    page.get_by_role("textbox", name="Field Path").fill("host")
    page.get_by_label("Action").select_option("Strip")
    page.get_by_role("button", name="Add Rule", exact=True).click()

    # Re-call: the field should be gone entirely (not aliased).
    page.get_by_role("button", name="Call", exact=True).click()
    # Need to wait for the new response to render — assert on the absence of host.
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)
    # The host key should not appear in the new tree.
    expect(page.locator(".tree-key", has_text="host:")).to_have_count(0)
    # Nothing should have been aliased (strip != mask).
    expect(page.locator(".tree-value", has_text=re.compile(r"_masked_host"))).to_have_count(0)


def test_set_injection_overrides_argument(dashboard_page: Page, stub: str) -> None:
    """A ``set`` injection on ``text`` overrides whatever the caller passed."""
    page = dashboard_page
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools/echo")

    # Add a set-mode injection on `text` with a sentinel value.
    injections_section = page.locator(".panel").filter(
        has=page.get_by_role("heading", name=re.compile(r"^Argument Injections"))
    )
    injections_section.locator("select").nth(0).select_option("text")
    injections_section.locator('input[type="text"]').nth(0).fill('"INJECTED"')
    injections_section.locator("select").nth(1).select_option("set (always)")
    injections_section.get_by_role("button", name="Add Injection", exact=True).click()

    # Call echo with a different value — upstream should see the injected one.
    page.get_by_role("textbox", name=re.compile(r"^text ")).fill("user-typed value")
    page.get_by_role("button", name="Call", exact=True).click()
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)
    # The stub echoes whatever it receives in {"received": text}. If injection
    # ran, "received" holds "INJECTED" — not "user-typed value".
    expect(page.locator(".tree-value", has_text="INJECTED")).to_be_visible()
    expect(page.locator(".tree-value", has_text="user-typed value")).to_have_count(0)


def _add_guardrail(page: Page, match: str, pattern: str) -> None:
    guardrails_section = page.locator(".panel").filter(
        has=page.get_by_role("heading", name=re.compile(r"^Argument Guardrails"))
    )
    # Form: select[0]=Argument, select[1]=Match; input[0]=Pattern, input[1]=Message.
    guardrails_section.locator("select").nth(0).select_option("text")
    guardrails_section.locator("select").nth(1).select_option(match)
    guardrails_section.locator('input[type="text"]').nth(0).fill(pattern)
    guardrails_section.get_by_role("button", name="Add Guardrail", exact=True).click()


@pytest.mark.parametrize(
    ("match_value", "pattern", "blocked_arg", "allowed_arg"),
    [
        ("equals", "BLOCK_ME", "BLOCK_ME", "block_me_lowercase"),
        ("regex", r"^secret-\d+$", "secret-42", "secret-foo"),
    ],
    ids=["equals", "regex"],
)
def test_guardrail_match_variants(
    dashboard_page: Page, stub: str, match_value: str, pattern: str, blocked_arg: str, allowed_arg: str
) -> None:
    page = dashboard_page
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools/echo")
    _add_guardrail(page, match=match_value, pattern=pattern)

    text_input = page.get_by_role("textbox", name=re.compile(r"^text "))
    call_button = page.get_by_role("button", name="Call", exact=True)

    # Allowed call goes through.
    text_input.fill(allowed_arg)
    call_button.click()
    expect(page.locator(".tree-value", has_text=allowed_arg)).to_be_visible(timeout=15_000)

    # Blocked call surfaces the guardrail message in the error panel.
    # ("Blocked by guardrail" also appears in the guardrails-table message column;
    # scope the assertion to the .try-error pre so the test isn't ambiguous.)
    text_input.fill(blocked_arg)
    call_button.click()
    expect(page.locator('pre[x-text="tryError"]')).to_contain_text("Blocked by guardrail", timeout=10_000)


def test_strip_via_api_persists_across_restart_of_target(dashboard_page: Page, stub: str) -> None:
    """Sanity: rules added through the UI are durable across deactivate/activate.

    Adds a strip rule, deactivates the target, reactivates, and confirms the
    next call still strips the field. Exercises the same persistence story
    as the marketplace tests but for custom targets.
    """
    page = dashboard_page
    _call_lookup_user(page)
    _open_manual_rule_entry(page)
    page.get_by_role("textbox", name="Field Path").fill("phone_number")
    page.get_by_label("Action").select_option("Strip")
    page.get_by_role("button", name="Add Rule", exact=True).click()
    expect(page.locator("code", has_text="phone_number")).to_be_visible()

    # Deactivate + activate through the JSON API (faster than dashboard nav).
    with api_client() as client:
        r = client.post(f"/api/targets/custom/{TARGET_ID}/deactivate")
        assert r.status_code == 200
        r = client.post(f"/api/targets/custom/{TARGET_ID}/activate")
        assert r.status_code == 200

    # Wait for upstream re-init.
    deadline_attempts = 30
    for _ in range(deadline_attempts):
        r = httpx.get(f"{E2E_BASE_URL}/api/targets/{TARGET_ID}/tools", timeout=5.0)
        if r.status_code == 200 and r.json().get("tools"):
            break
    else:
        pytest.fail("stub did not re-initialize after activate")

    # Strip rule still in effect on a fresh call.
    page.goto(f"{E2E_BASE_URL}/targets/{TARGET_ID}/tools/lookup_user")
    page.get_by_role("textbox", name=re.compile(r"^name ")).fill("alice")
    page.get_by_role("button", name="Call", exact=True).click()
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)
    expect(page.locator(".tree-key", has_text="phone_number:")).to_have_count(0)
