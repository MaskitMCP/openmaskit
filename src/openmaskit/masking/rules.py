"""Masking rule matching and request interception models."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class MaskingRule:
    tool_name: str
    field_path: str
    alias_prefix: str | None = None
    action: str = "mask"
    active: bool = True
    id: int | None = None

    @property
    def effective_prefix(self) -> str:
        if self.alias_prefix:
            return self.alias_prefix
        return "_masked_" + self.field_path.rsplit(".", maxsplit=1)[-1]

    def matches_tool(self, tool_name: str) -> bool:
        return self.tool_name == "*" or self.tool_name == tool_name


@dataclass
class ArgumentGuardrail:
    tool_name: str
    argument_name: str
    match_type: str
    pattern: str
    message: str = "Blocked by guardrail"
    active: bool = True
    id: int | None = None

    def matches_tool(self, tool_name: str) -> bool:
        return self.tool_name == "*" or self.tool_name == tool_name


@dataclass
class ArgumentInjection:
    tool_name: str
    argument_name: str
    value: str
    mode: str = "set"
    active: bool = True
    id: int | None = None

    def matches_tool(self, tool_name: str) -> bool:
        return self.tool_name == "*" or self.tool_name == tool_name


def get_nested_value(data: dict[str, Any], path: str) -> Any | None:
    """Get a value from a nested dict using dot-notation path."""
    parts = path.split(".")
    current = data
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def set_nested_value(data: dict[str, Any], path: str, value: Any) -> bool:
    """Set a value in a nested dict using dot-notation path. Returns True if set."""
    parts = path.split(".")
    current = data
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return False
        next_val = current.get(part)
        if not isinstance(next_val, dict):
            return False
        current = next_val
    if not isinstance(current, dict):
        return False
    if parts[-1] in current:
        current[parts[-1]] = value
        return True
    return False


def delete_nested_value(data: dict[str, Any], path: str) -> bool:
    """Delete a value from a nested dict using dot-notation path. Returns True if deleted."""
    parts = path.split(".")
    current = data
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return False
        next_val = current.get(part)
        if not isinstance(next_val, dict):
            return False
        current = next_val
    if not isinstance(current, dict):
        return False
    if parts[-1] in current:
        del current[parts[-1]]
        return True
    return False


# --- List-fanout walkers -----------------------------------------------------
#
# The helpers above resolve a single dot-path through pure dicts. They return
# None/False the moment an intermediate value is a list. The walkers below
# fan out implicitly across lists at every depth, so `categories.id` against
# `{"categories": [{"id": 1}, {"id": 2}]}` reaches both `id` values.


def walk_and_mask(
    data: Any, path: str, mask_fn: Callable[[str], str]
) -> int:
    """Walk `data` along the dot-path, calling `mask_fn(value)` on every
    string leaf reached at the terminal segment, replacing in place. Intermediate
    list-typed values are recursed into transparently. Non-string leaves are
    skipped. Returns the number of replacements made.
    """
    parts = path.split(".")
    return _walk_mask(data, parts, mask_fn)


def _walk_mask(data: Any, parts: list[str], mask_fn: Callable[[str], str]) -> int:
    if isinstance(data, list):
        total = 0
        for item in data:
            total += _walk_mask(item, parts, mask_fn)
        return total
    if not isinstance(data, dict) or not parts:
        return 0
    key = parts[0]
    if key not in data:
        return 0
    rest = parts[1:]
    if not rest:
        return _mask_terminal(data, key, mask_fn)
    return _walk_mask(data[key], rest, mask_fn)


def _mask_terminal(
    container: dict, key: str, mask_fn: Callable[[str], str]
) -> int:
    # Only string leaves are masked. Non-string scalars (int/float/bool) are
    # left untouched: stringifying them would change the field's type on the
    # way back to the upstream (alias → cached "1" string → upstream gets
    # `"id": "1"` when it expected `"id": 1`), which breaks strictly-typed
    # MCP servers. Use a structured rule on a string-typed field, or have the
    # upstream emit the value as a string, if you need this masked.
    value = container[key]
    if isinstance(value, str):
        container[key] = mask_fn(value)
        return 1
    if isinstance(value, list):
        total = 0
        for i, item in enumerate(value):
            if isinstance(item, str):
                value[i] = mask_fn(item)
                total += 1
        return total
    return 0


def walk_and_delete(data: Any, path: str) -> int:
    """Walk `data` along the dot-path and delete the terminal key wherever it
    is reached, fanning out across lists. Returns the number of deletions.
    """
    parts = path.split(".")
    return _walk_delete(data, parts)


def _walk_delete(data: Any, parts: list[str]) -> int:
    if isinstance(data, list):
        total = 0
        for item in data:
            total += _walk_delete(item, parts)
        return total
    if not isinstance(data, dict) or not parts:
        return 0
    key = parts[0]
    if key not in data:
        return 0
    rest = parts[1:]
    if not rest:
        del data[key]
        return 1
    return _walk_delete(data[key], rest)


def walk_strings(data: Any, fn: Callable[[str], str]) -> Any:
    """Walk arbitrarily nested dicts/lists, calling `fn(s)` on every string
    leaf and replacing it in place. Returns `data` (root may be a string, in
    which case the new value is returned)."""
    if isinstance(data, str):
        return fn(data)
    if isinstance(data, list):
        for i, item in enumerate(data):
            data[i] = walk_strings(item, fn)
        return data
    if isinstance(data, dict):
        for k in list(data.keys()):
            data[k] = walk_strings(data[k], fn)
        return data
    return data
