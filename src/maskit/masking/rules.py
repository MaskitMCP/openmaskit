"""Masking rule matching."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MaskingRule:
    tool_name: str
    field_path: str
    alias_prefix: str | None = None
    active: bool = True
    id: int | None = None

    @property
    def effective_prefix(self) -> str:
        if self.alias_prefix:
            return self.alias_prefix
        # Use the last segment of the path as the prefix
        return self.field_path.rsplit(".", maxsplit=1)[-1]

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
