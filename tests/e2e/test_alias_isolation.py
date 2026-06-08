"""End-to-end: aliases are scoped per target.

Two custom stdio targets, same masking rule on the same field path. The
composite ``(target_name, alias)`` PK in ``mappings`` means each target's
counter is independent, so both produce ``email_1`` for *their* first email
without colliding.
"""

from __future__ import annotations

import re

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import E2E_BASE_URL, api_client, install_stub_via_api

pytestmark = pytest.mark.e2e


def _add_mask_rule(target_id: str, *, field_path: str, alias_prefix: str) -> None:
    """Add a path-based mask rule via the JSON API (skip the UI for speed)."""
    with api_client() as client:
        r = client.post(
            f"/api/targets/{target_id}/rules/create",
            json={
                "tool_name": "lookup_user",
                "field_path": field_path,
                "alias_prefix": alias_prefix,
                "action": "mask",
            },
        )
        r.raise_for_status()


def _call_lookup_user(page: Page, target_id: str, *, name: str) -> None:
    page.goto(f"{E2E_BASE_URL}/targets/{target_id}/tools/lookup_user")
    page.get_by_role("textbox", name=re.compile(r"^name ")).fill(name)
    page.get_by_role("button", name="Call", exact=True).click()
    expect(page.locator(".tree-leaf").first).to_be_visible(timeout=15_000)


def test_aliases_namespaced_per_target(dashboard_page: Page) -> None:
    page = dashboard_page

    install_stub_via_api("stub-a")
    install_stub_via_api("stub-b")

    # Same rule on both targets — both should mint their own ``email_1`` for
    # their first email, and the two mappings tables should not interfere.
    _add_mask_rule("stub-a", field_path="email", alias_prefix="email")
    _add_mask_rule("stub-b", field_path="email", alias_prefix="email")

    _call_lookup_user(page, "stub-a", name="alice")
    expect(page.locator(".tree-value", has_text="email_1")).to_be_visible()

    _call_lookup_user(page, "stub-b", name="alice")
    # If the namespaces were shared, stub-b's first email would get email_2
    # because the counter would have advanced past email_1 on stub-a.
    expect(page.locator(".tree-value", has_text="email_1")).to_be_visible()

    # The masking engine batches alias writes — pending entries flush to the
    # DB every ~1s. Wait that out before cross-checking via the mappings API.
    import time
    time.sleep(1.5)
    r_a = httpx.get(f"{E2E_BASE_URL}/api/targets/stub-a/mappings", timeout=5.0).json()["mappings"]
    r_b = httpx.get(f"{E2E_BASE_URL}/api/targets/stub-b/mappings", timeout=5.0).json()["mappings"]
    by_alias_a = {m["alias"]: m["real_value"] for m in r_a}
    by_alias_b = {m["alias"]: m["real_value"] for m in r_b}
    # Both targets hold their own ``email_1`` — proving the namespaces don't share.
    assert by_alias_a.get("email_1") == "alice@example.com"
    assert by_alias_b.get("email_1") == "alice@example.com"
