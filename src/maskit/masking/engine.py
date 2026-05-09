"""Masking engine: mask values in responses, unmask in arguments."""

from __future__ import annotations

import json
import logging
from typing import Any

from maskit.masking.rules import MaskingRule, get_nested_value, set_nested_value
from maskit.masking.store import MaskingStore

logger = logging.getLogger(__name__)


class MaskingEngine:
    """
    Synchronous masking/unmasking using an in-memory cache.
    The cache is synced with the database periodically via flush_pending/load_aliases.
    """

    def __init__(self, rules: list[MaskingRule], store: MaskingStore):
        self._rules = rules
        self._store = store
        self._alias_cache: dict[str, str] = {}  # alias -> real_value
        self._reverse_cache: dict[str, dict[str, str]] = {}  # (field_path, real_value) -> alias
        self._pending_writes: list[tuple[str, str, str, str]] = []
        self._counters: dict[str, int] = {}

    @property
    def rules(self) -> list[MaskingRule]:
        return self._rules

    def set_rules(self, rules: list[MaskingRule]):
        self._rules = rules

    async def load_aliases(self):
        """Load all existing aliases into memory for fast lookup."""
        self._alias_cache = await self._store.get_all_aliases()
        self._reverse_cache.clear()
        self._counters.clear()
        for alias, real_value in self._alias_cache.items():
            parts = alias.rsplit("_", 1)
            if len(parts) == 2 and parts[1].isdigit():
                prefix = parts[0]
                self._reverse_cache.setdefault(prefix, {})[real_value] = alias
                self._counters[prefix] = max(
                    self._counters.get(prefix, 0), int(parts[1])
                )

    async def flush_pending(self):
        """Write pending alias mappings to the database."""
        writes = self._pending_writes[:]
        self._pending_writes.clear()
        for alias, real_value, tool_name, field_path in writes:
            prefix = alias.rsplit("_", 1)[0]
            await self._store.get_or_create_alias(real_value, tool_name, field_path, prefix)

    def mask_response(self, tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
        """Mask sensitive fields in a tool call response (synchronous, uses cache)."""
        applicable_rules = [
            r for r in self._rules if r.active and r.matches_tool(tool_name)
        ]
        if not applicable_rules:
            return result

        if "structuredContent" in result and isinstance(result["structuredContent"], dict):
            result["structuredContent"] = self._mask_dict(
                result["structuredContent"], tool_name, applicable_rules
            )

        if "content" in result and isinstance(result["content"], list):
            result["content"] = [
                self._mask_content_block(block, tool_name, applicable_rules)
                for block in result["content"]
            ]

        return result

    def unmask_arguments(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Replace masked aliases in tool call arguments with real values."""
        if not self._alias_cache:
            return arguments
        return self._unmask_recursive(arguments)

    def _mask_dict(
        self, data: dict[str, Any], tool_name: str, rules: list[MaskingRule]
    ) -> dict[str, Any]:
        for rule in rules:
            value = get_nested_value(data, rule.field_path)
            if value is not None and isinstance(value, str):
                alias = self._get_or_create_alias(
                    value, tool_name, rule.field_path, rule.effective_prefix
                )
                set_nested_value(data, rule.field_path, alias)
        return data

    def _get_or_create_alias(
        self, real_value: str, tool_name: str, field_path: str, prefix: str
    ) -> str:
        """Get existing or create new alias (in-memory, deferred DB write)."""
        prefix_map = self._reverse_cache.get(prefix, {})
        if real_value in prefix_map:
            return prefix_map[real_value]

        counter = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = counter
        new_alias = f"{prefix}_{counter}"

        self._alias_cache[new_alias] = real_value
        self._reverse_cache.setdefault(prefix, {})[real_value] = new_alias
        self._pending_writes.append((new_alias, real_value, tool_name, field_path))
        return new_alias

    def _mask_content_block(
        self, block: dict[str, Any], tool_name: str, rules: list[MaskingRule]
    ) -> dict[str, Any]:
        if block.get("type") != "text":
            return block

        text = block.get("text", "")
        if not text:
            return block

        # Try parsing as JSON
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                masked = self._mask_dict(parsed, tool_name, rules)
                block["text"] = json.dumps(masked)
                return block
        except (json.JSONDecodeError, ValueError):
            pass

        # For plain text, replace known real values with their aliases
        for rule in rules:
            prefix = rule.effective_prefix
            prefix_map = self._reverse_cache.get(prefix, {})
            for real_value, alias in prefix_map.items():
                if real_value in text:
                    text = text.replace(real_value, alias)
        block["text"] = text
        return block

    def _unmask_recursive(self, data: Any) -> Any:
        if isinstance(data, str):
            if data in self._alias_cache:
                return self._alias_cache[data]
            for alias, real_value in self._alias_cache.items():
                if alias in data:
                    data = data.replace(alias, real_value)
            return data
        elif isinstance(data, dict):
            return {k: self._unmask_recursive(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._unmask_recursive(item) for item in data]
        return data
