"""Masking engine: mask values in responses, unmask in arguments."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import ahocorasick

from openmaskit.masking.mappers import ResponseMapper
from openmaskit.masking.parsing import serialize, try_parse_structured
from openmaskit.masking.rules import (
    ArgumentGuardrail,
    ArgumentInjection,
    MaskingRule,
    delete_nested_value,
    get_nested_value,
    set_nested_value,
    walk_and_delete,
    walk_and_mask,
    walk_strings,
)
from openmaskit.masking.store import MaskingStore

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
        self._automaton: ahocorasick.Automaton | None = None
        self._aliases_dirty: bool = True
        self._pending_writes: list[tuple[str, str, str, str]] = []
        self._counters: dict[str, int] = {}
        self._mappers: list[ResponseMapper] = []
        self._compiled_patterns: dict[int, re.Pattern] = {}
        self._guardrails: list[ArgumentGuardrail] = []
        self._compiled_guardrails: dict[int, re.Pattern] = {}
        self._injections: list[ArgumentInjection] = []

    @property
    def store(self) -> MaskingStore:
        return self._store

    @property
    def rules(self) -> list[MaskingRule]:
        return self._rules

    @rules.setter
    def rules(self, value: list[MaskingRule]):
        self._rules = value

    @property
    def mappers(self) -> list[ResponseMapper]:
        return self._mappers

    @mappers.setter
    def mappers(self, value: list[ResponseMapper]):
        self._mappers = value

    @property
    def compiled_patterns(self) -> dict[int, re.Pattern]:
        return self._compiled_patterns

    @property
    def alias_cache(self) -> dict[str, str]:
        return self._alias_cache

    @property
    def has_pending_writes(self) -> bool:
        return bool(self._pending_writes)

    def get_new_masks_since(self, offset: int) -> list[tuple[str, str, str, str]]:
        return self._pending_writes[offset:]

    @property
    def pending_writes_count(self) -> int:
        return len(self._pending_writes)

    def set_rules(self, rules: list[MaskingRule]):
        self._rules = rules

    def add_rule(self, rule: MaskingRule):
        self._rules.append(rule)

    def remove_rule(self, rule_id: int):
        self._rules = [r for r in self._rules if r.id != rule_id]

    def add_mapper(self, mapper: ResponseMapper):
        self._mappers.append(mapper)
        if mapper.mapper_type == "regex_replace" and mapper.id:
            try:
                self._compiled_patterns[mapper.id] = re.compile(mapper.pattern)
            except re.error:
                pass

    def remove_mapper(self, mapper_id: int):
        self._mappers = [m for m in self._mappers if m.id != mapper_id]
        self._compiled_patterns.pop(mapper_id, None)

    def get_mapper(self, mapper_id: int) -> ResponseMapper | None:
        return next((m for m in self._mappers if m.id == mapper_id), None)

    def update_mapper_pattern(self, mapper_id: int, pattern: str, alias_prefix: str):
        mapper = self.get_mapper(mapper_id)
        if mapper:
            mapper.pattern = pattern
            mapper.alias_prefix = alias_prefix
            if mapper.mapper_type == "regex_replace":
                self._compiled_patterns[mapper_id] = re.compile(pattern)

    # --- Guardrail management ---

    @property
    def guardrails(self) -> list[ArgumentGuardrail]:
        return self._guardrails

    @guardrails.setter
    def guardrails(self, value: list[ArgumentGuardrail]):
        self._guardrails = value

    def add_guardrail(self, guardrail: ArgumentGuardrail):
        self._guardrails.append(guardrail)
        if guardrail.match_type == "regex" and guardrail.id is not None:
            try:
                self._compiled_guardrails[guardrail.id] = re.compile(guardrail.pattern)
            except re.error:
                pass

    def get_guardrail(self, guardrail_id: int) -> ArgumentGuardrail | None:
        """Get guardrail by ID."""
        for g in self._guardrails:
            if g.id == guardrail_id:
                return g
        return None

    def remove_guardrail(self, guardrail_id: int):
        self._guardrails = [g for g in self._guardrails if g.id != guardrail_id]
        self._compiled_guardrails.pop(guardrail_id, None)

    async def load_guardrails(self):
        self._guardrails = await self._store.get_guardrails(target_name=self._target_name)
        self._compiled_guardrails = {}
        for g in self._guardrails:
            if g.match_type == "regex" and g.id is not None:
                try:
                    self._compiled_guardrails[g.id] = re.compile(g.pattern)
                except re.error as exc:
                    logger.warning("Invalid regex in guardrail %d: %s", g.id, exc)

    def check_guardrails(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        """Check arguments against guardrails. Returns error message or None."""
        applicable = [g for g in self._guardrails if g.active and g.matches_tool(tool_name)]
        for guardrail in applicable:
            if guardrail.argument_name == "*":
                if self._check_guardrail_recursive(arguments, guardrail):
                    return guardrail.message
            else:
                value = arguments.get(guardrail.argument_name)
                if value is not None and isinstance(value, str):
                    if self._matches_guardrail(value, guardrail):
                        return guardrail.message
        return None

    def _check_guardrail_recursive(self, data: Any, guardrail: ArgumentGuardrail) -> bool:
        if isinstance(data, str):
            return self._matches_guardrail(data, guardrail)
        elif isinstance(data, dict):
            return any(self._check_guardrail_recursive(v, guardrail) for v in data.values())
        elif isinstance(data, list):
            return any(self._check_guardrail_recursive(item, guardrail) for item in data)
        return False

    def _matches_guardrail(self, value: str, guardrail: ArgumentGuardrail) -> bool:
        if guardrail.match_type == "equals":
            return value == guardrail.pattern
        elif guardrail.match_type == "contains":
            return guardrail.pattern.casefold() in value.casefold()
        elif guardrail.match_type == "regex":
            compiled = self._compiled_guardrails.get(guardrail.id)
            if compiled:
                return bool(compiled.search(value))
        return False

    # --- Injection management ---

    @property
    def injections(self) -> list[ArgumentInjection]:
        return self._injections

    @injections.setter
    def injections(self, value: list[ArgumentInjection]):
        self._injections = value

    def add_injection(self, injection: ArgumentInjection):
        self._injections.append(injection)

    def remove_injection(self, injection_id: int):
        self._injections = [i for i in self._injections if i.id != injection_id]

    async def load_injections(self):
        self._injections = await self._store.get_injections(target_name=self._target_name)

    def apply_injections(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Apply argument injections. Returns modified arguments."""
        applicable = [i for i in self._injections if i.active and i.matches_tool(tool_name)]
        for injection in applicable:
            try:
                parsed_value = json.loads(injection.value)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Invalid JSON in injection %d (tool=%s, arg=%s): %s",
                    injection.id, tool_name, injection.argument_name, exc
                )
                continue

            if injection.mode == "set":
                arguments[injection.argument_name] = parsed_value
            elif injection.mode == "default":
                if injection.argument_name not in arguments:
                    arguments[injection.argument_name] = parsed_value
            elif injection.mode == "append":
                existing = arguments.get(injection.argument_name)
                if existing is None:
                    arguments[injection.argument_name] = parsed_value
                elif isinstance(existing, str) and isinstance(parsed_value, str):
                    arguments[injection.argument_name] = existing + parsed_value
                elif isinstance(existing, list):
                    if isinstance(parsed_value, list):
                        arguments[injection.argument_name] = existing + parsed_value
                    else:
                        existing.append(parsed_value)
        return arguments

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
        self._aliases_dirty = True

    def _ensure_automaton(self) -> ahocorasick.Automaton | None:
        if not self._aliases_dirty:
            return self._automaton
        if not self._alias_cache:
            self._automaton = None
        else:
            A = ahocorasick.Automaton()
            for alias, real_value in self._alias_cache.items():
                A.add_word(alias, (alias, real_value))
            A.make_automaton()
            self._automaton = A
        self._aliases_dirty = False
        return self._automaton

    async def load_rules(self):
        """Load masking rules from the store, replacing any in-memory rules.

        Mirrors load_aliases / load_mappers / load_guardrails / load_injections —
        used on target hot-add so rules persisted by prior sessions survive a
        deactivate/activate cycle.
        """
        self._rules = await self._store.get_rules(target_name=self._target_name)

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
        """Write pending alias mappings to the database.

        Uses ``store.persist_alias`` so the engine's per-target counter — the
        only counter that observes every mint — is the source of truth. The
        previous implementation called ``store.get_or_create_alias`` and threw
        away the alias the store returned, which silently diverged the
        in-memory cache from the DB row whenever the store's counter and the
        engine's counter disagreed.
        """
        writes = self._pending_writes[:]
        self._pending_writes.clear()
        for alias, real_value, tool_name, field_path in writes:
            await self._store.persist_alias(
                self._target_name, alias, real_value, tool_name, field_path,
            )

    def mask_response(self, tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
        """Mask sensitive fields in a tool call response (synchronous, uses cache)."""
        applicable_rules = [
            r for r in self._rules if r.active and r.matches_tool(tool_name)
        ]
        if applicable_rules:
            if "structuredContent" in result and isinstance(result["structuredContent"], (dict, list)):
                result["structuredContent"] = self._mask_structured(
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
        if applicable_mappers:
            if "structuredContent" in result and isinstance(result["structuredContent"], (dict, list)):
                self._apply_mappers_to_structured(
                    result["structuredContent"], tool_name, applicable_mappers
                )
            if "content" in result and isinstance(result["content"], list):
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

    def _mask_structured(
        self, data: Any, tool_name: str, rules: list[MaskingRule]
    ) -> Any:
        """Apply rules to an arbitrarily nested dict/list payload. Each rule's
        `field_path` is resolved with implicit list-fanout — `a.b.c` applies
        to every `c` reachable along `a.b`, regardless of how many list nestings
        sit on the way."""
        if not isinstance(data, (dict, list)):
            return data
        for rule in rules:
            if rule.action == "strip":
                walk_and_delete(data, rule.field_path)
            else:
                def _mask_one(value: str, rule: MaskingRule = rule) -> str:
                    return self._get_or_create_alias(
                        value, tool_name, rule.field_path, rule.effective_prefix
                    )
                walk_and_mask(data, rule.field_path, _mask_one)
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
        self._aliases_dirty = True
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
        if parse_result is not None and isinstance(parse_result.data, (dict, list)):
            masked = self._mask_structured(parse_result.data, tool_name, rules)
            block["text"] = serialize(masked, parse_result.format)
            return block

        # For plain text, replace known real values with their aliases (skip strip rules)
        for rule in rules:
            if rule.action == "strip":
                continue
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
            automaton = self._ensure_automaton()
            if automaton is None:
                return data
            parts: list[str] = []
            last_end = 0
            matched = False
            for end_idx, (alias, real_value) in automaton.iter_long(data):
                start = end_idx - len(alias) + 1
                parts.append(data[last_end:start])
                parts.append(real_value)
                last_end = end_idx + 1
                matched = True
            if not matched:
                return data
            parts.append(data[last_end:])
            return "".join(parts)
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

    def _apply_mappers_to_structured(
        self,
        data: Any,
        tool_name: str,
        mappers: list[ResponseMapper],
    ) -> None:
        """Apply mappers to an arbitrarily nested dict/list payload (in place).
        Regex mappers scan every string leaf; json_field_mask mappers walk
        the dot-path with implicit list-fanout."""
        if not isinstance(data, (dict, list)):
            return
        for mapper in mappers:
            if mapper.mapper_type == "regex_replace":
                if mapper.id in self._compiled_patterns:
                    def _per_str(value: str, mapper: ResponseMapper = mapper) -> str:
                        return self._apply_regex_mapper(value, tool_name, mapper)
                    walk_strings(data, _per_str)
            elif mapper.mapper_type == "json_field_mask":
                path_parts = mapper.pattern.split(".")
                self._mask_at_json_path(data, path_parts, tool_name, mapper)

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
            # String-only by design: stringifying non-string scalars would
            # change the field's type on the unmask round-trip and break
            # strictly-typed upstream tools. Mirrors rule-path semantics in
            # rules._mask_terminal.
            if isinstance(value, str):
                data[current_key] = self._get_or_create_alias(
                    value, tool_name, f"mapper:{mapper.id}:{mapper.pattern}", mapper.alias_prefix
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
