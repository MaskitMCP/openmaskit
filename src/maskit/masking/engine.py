"""Masking engine: mask values in responses, unmask in arguments."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from maskit.masking.mappers import ResponseMapper
from maskit.masking.parsing import serialize, try_parse_structured
from maskit.masking.rules import MaskingRule, get_nested_value, set_nested_value
from maskit.masking.store import MaskingStore

logger = logging.getLogger(__name__)


class MaskingEngine:
    """
    Synchronous masking/unmasking using an in-memory cache.
    The cache is synced with the database periodically via flush_pending/load_aliases.
    """

    def __init__(self, rules: list[MaskingRule], store: MaskingStore, target_name: str = "default"):
        self._rules = rules
        self._store = store
        self._target_name = target_name
        self._alias_cache: dict[str, str] = {}  # alias -> real_value
        self._reverse_cache: dict[str, dict[str, str]] = {}  # (field_path, real_value) -> alias
        self._pending_writes: list[tuple[str, str, str, str]] = []
        self._counters: dict[str, int] = {}
        self._mappers: list[ResponseMapper] = []
        self._compiled_patterns: dict[int, re.Pattern] = {}

    @property
    def rules(self) -> list[MaskingRule]:
        return self._rules

    @property
    def mappers(self) -> list[ResponseMapper]:
        return self._mappers

    def set_rules(self, rules: list[MaskingRule]):
        self._rules = rules

    async def load_aliases(self):
        """Load all existing aliases into memory for fast lookup."""
        self._alias_cache = await self._store.get_all_aliases(target_name=self._target_name)
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

    async def load_mappers(self):
        """Load response mappers from store and compile patterns."""
        self._mappers = await self._store.get_mappers(target_name=self._target_name)
        self._compiled_patterns = {}
        for m in self._mappers:
            if m.mapper_type == "regex_replace":
                try:
                    self._compiled_patterns[m.id] = re.compile(m.pattern)
                except re.error as exc:
                    logger.warning("Invalid regex in mapper %d: %s", m.id, exc)

    async def flush_pending(self):
        """Write pending alias mappings to the database."""
        writes = self._pending_writes[:]
        self._pending_writes.clear()
        for alias, real_value, tool_name, field_path in writes:
            prefix = alias.rsplit("_", 1)[0]
            await self._store.get_or_create_alias(real_value, tool_name, field_path, prefix, self._target_name)

    def mask_response(self, tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
        """Mask sensitive fields in a tool call response (synchronous, uses cache)."""
        applicable_rules = [
            r for r in self._rules if r.active and r.matches_tool(tool_name)
        ]
        if applicable_rules:
            if "structuredContent" in result and isinstance(result["structuredContent"], dict):
                result["structuredContent"] = self._mask_dict(
                    result["structuredContent"], tool_name, applicable_rules
                )

            if "content" in result and isinstance(result["content"], list):
                result["content"] = [
                    self._mask_content_block(block, tool_name, applicable_rules)
                    for block in result["content"]
                ]

        applicable_mappers = sorted(
            [m for m in self._mappers if m.active and m.matches_tool(tool_name)],
            key=lambda m: m.order,
        )
        if applicable_mappers and "content" in result and isinstance(result["content"], list):
            result["content"] = [
                self._apply_mappers_to_block(block, tool_name, applicable_mappers)
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

        parse_result = try_parse_structured(text)
        if parse_result is not None and isinstance(parse_result.data, dict):
            masked = self._mask_dict(parse_result.data, tool_name, rules)
            block["text"] = serialize(masked, parse_result.format)
            return block

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
            # Sort by length descending to prevent partial matches (cred_10 before cred_1)
            for alias, real_value in sorted(
                self._alias_cache.items(), key=lambda x: len(x[0]), reverse=True
            ):
                if alias in data:
                    data = data.replace(alias, real_value)
            return data
        elif isinstance(data, dict):
            return {k: self._unmask_recursive(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._unmask_recursive(item) for item in data]
        return data

    # --- Response Mapper methods ---

    def _apply_mappers_to_block(
        self, block: dict[str, Any], tool_name: str, mappers: list[ResponseMapper]
    ) -> dict[str, Any]:
        if block.get("type") != "text":
            return block
        text = block.get("text", "")
        if not text:
            return block
        for mapper in mappers:
            if mapper.mapper_type == "regex_replace":
                if mapper.id in self._compiled_patterns:
                    text = self._apply_regex_mapper(text, tool_name, mapper)
            elif mapper.mapper_type == "json_field_mask":
                text = self._apply_json_field_mask(text, tool_name, mapper)
        block["text"] = text
        return block

    def _apply_regex_mapper(
        self, text: str, tool_name: str, mapper: ResponseMapper
    ) -> str:
        compiled = self._compiled_patterns[mapper.id]

        def replacer(match: re.Match) -> str:
            if match.lastindex and match.lastindex >= 1:
                captured = match.group(1)
                alias = self._get_or_create_alias(
                    captured, tool_name, f"mapper:{mapper.id}", mapper.alias_prefix
                )
                start, end = match.span(1)
                full_start, _ = match.span(0)
                return match.group(0)[: start - full_start] + alias + match.group(0)[end - full_start :]
            else:
                alias = self._get_or_create_alias(
                    match.group(0), tool_name, f"mapper:{mapper.id}", mapper.alias_prefix
                )
                return alias

        return compiled.sub(replacer, text)

    def _apply_json_field_mask(
        self, text: str, tool_name: str, mapper: ResponseMapper
    ) -> str:
        parse_result = try_parse_structured(text)
        if parse_result is None:
            return text

        data = parse_result.data
        path_parts = mapper.pattern.split(".")
        if self._mask_at_json_path(data, path_parts, tool_name, mapper):
            return serialize(data, parse_result.format)
        return text

    def _mask_at_json_path(
        self, data: Any, path_parts: list[str], tool_name: str, mapper: ResponseMapper
    ) -> bool:
        if not path_parts:
            return False

        if isinstance(data, list):
            any_masked = False
            for item in data:
                if self._mask_at_json_path(item, path_parts, tool_name, mapper):
                    any_masked = True
            return any_masked

        if not isinstance(data, dict):
            return False

        current_key = path_parts[0]
        remaining = path_parts[1:]

        if current_key not in data:
            return False

        value = data[current_key]

        if not remaining:
            if isinstance(value, str):
                data[current_key] = self._get_or_create_alias(
                    value, tool_name, f"mapper:{mapper.id}:{mapper.pattern}", mapper.alias_prefix
                )
                return True
            elif isinstance(value, (int, float, bool)):
                data[current_key] = self._get_or_create_alias(
                    str(value), tool_name, f"mapper:{mapper.id}:{mapper.pattern}", mapper.alias_prefix
                )
                return True
            elif isinstance(value, list):
                any_masked = False
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        value[i] = self._get_or_create_alias(
                            item, tool_name, f"mapper:{mapper.id}:{mapper.pattern}", mapper.alias_prefix
                        )
                        any_masked = True
                return any_masked
            return False

        if isinstance(value, list):
            any_masked = False
            for item in value:
                if self._mask_at_json_path(item, remaining, tool_name, mapper):
                    any_masked = True
            return any_masked
        elif isinstance(value, dict):
            return self._mask_at_json_path(value, remaining, tool_name, mapper)
        return False
