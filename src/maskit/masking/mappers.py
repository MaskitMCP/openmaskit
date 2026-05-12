"""Response mapper definitions."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResponseMapper:
    tool_name: str
    mapper_type: str
    pattern: str
    alias_prefix: str
    order: int = 0
    active: bool = True
    id: int | None = None
    config: dict | None = field(default=None)

    def matches_tool(self, tool_name: str) -> bool:
        return self.tool_name == "*" or self.tool_name == tool_name
