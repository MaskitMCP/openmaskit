"""Static guards for the tool-detail panel layout and tutorial integrity.

These tests don't run a browser; they parse the HTML and tutorial JSON files
on disk and assert invariants that protect against silent regressions when
the panels or tutorials change.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).parent.parent / "src" / "openmaskit" / "web" / "static"
TOOL_DETAIL_HTML = STATIC_DIR / "tool_detail.html"
TUTORIALS_DIR = STATIC_DIR / "tutorials"


@pytest.fixture(scope="module")
def tool_detail_html() -> str:
    return TOOL_DETAIL_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tutorial_files() -> list[Path]:
    return sorted(TUTORIALS_DIR.glob("*.json"))


def test_single_masking_panel(tool_detail_html: str) -> None:
    """The Input/Output Masking split is merged into one Masking panel."""
    h2_texts = [
        re.sub(r"<[^>]+>", "", block).strip().split("\n", 1)[0].strip()
        for block in re.findall(r"<h2[^>]*>(.*?)</h2>", tool_detail_html, re.DOTALL)
    ]
    masking_headings = [t for t in h2_texts if t.startswith("Masking")]
    assert len(masking_headings) == 1, (
        f"Expected exactly one <h2> starting with 'Masking', got {masking_headings}"
    )
    assert "Input Masking" not in tool_detail_html
    assert "Output Masking" not in tool_detail_html


def test_tutorial_files_valid(tutorial_files: list[Path]) -> None:
    """Every tutorial JSON file parses and has the expected shape."""
    assert tutorial_files, "no tutorial files found"
    for path in tutorial_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "id" in data and isinstance(data["id"], str) and data["id"], path.name
        assert "title" in data and isinstance(data["title"], str) and data["title"], path.name
        steps = data.get("steps")
        assert isinstance(steps, list) and steps, f"{path.name} has no steps"
        for i, step in enumerate(steps):
            assert "text" in step and step["text"], f"{path.name} step {i} missing text"
            # target may be null for centered intro steps with no anchor element
            assert "target" in step, f"{path.name} step {i} missing target key"


def test_tutorial_ids_referenced_exist(
    tool_detail_html: str, tutorial_files: list[Path]
) -> None:
    """Every startTutorial('...') id in the HTML has a matching JSON file."""
    referenced = set(re.findall(r"startTutorial\(\s*['\"]([^'\"]+)['\"]", tool_detail_html))
    # Also catch the conditional form: startTutorial(cond ? 'a' : 'b')
    for match in re.finditer(
        r"startTutorial\([^)]*\?\s*['\"]([^'\"]+)['\"]\s*:\s*['\"]([^'\"]+)['\"]",
        tool_detail_html,
    ):
        referenced.add(match.group(1))
        referenced.add(match.group(2))

    available = {p.stem for p in tutorial_files}
    missing = referenced - available
    assert not missing, f"HTML references tutorial ids with no JSON file: {missing}"


def test_old_masking_tutorial_ids_gone(
    tool_detail_html: str, tutorial_files: list[Path]
) -> None:
    """The pre-merge tutorial ids/files must no longer exist."""
    legacy = {"input-masking", "output-mappers", "output-mappers-with-result"}
    stems = {p.stem for p in tutorial_files}
    assert not (legacy & stems), f"legacy tutorial files still present: {legacy & stems}"
    for legacy_id in legacy:
        assert f"startTutorial('{legacy_id}')" not in tool_detail_html
        assert f'startTutorial("{legacy_id}")' not in tool_detail_html
