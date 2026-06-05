"""Utilities for parsing text that may be JSON or Python repr."""

from __future__ import annotations

import ast
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_PARSE_LEN = 1024 * 1024  # 1 MiB


def get_max_parse_len() -> int:
    """Max input length passed to ``json.loads`` / ``ast.literal_eval``, in chars.

    Reads ``OPENMASKIT_MAX_PARSE_BYTES`` from the environment; falls back to
    the default if unset, non-numeric, or non-positive. Bounds memory usage
    from a malicious upstream MCP server that sends a giant nested literal.
    """
    raw = os.environ.get("OPENMASKIT_MAX_PARSE_BYTES")
    if raw is None:
        return DEFAULT_MAX_PARSE_LEN
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_PARSE_LEN
    return value if value > 0 else DEFAULT_MAX_PARSE_LEN


@dataclass
class ParseResult:
    data: Any
    format: str  # "json" | "python_repr"


def try_parse_structured(text: str) -> ParseResult | None:
    """Try JSON first, fall back to ast.literal_eval. Returns None if neither works.

    Input larger than ``get_max_parse_len()`` is rejected outright (returns
    None). ``ast.literal_eval`` builds an AST sized roughly proportional to
    the input, so an unbounded upstream response can OOM the proxy; the cap
    is the simplest defense.
    """
    if len(text) > get_max_parse_len():
        logger.warning(
            "try_parse_structured: input length %d exceeds cap %d; skipping parse",
            len(text),
            get_max_parse_len(),
        )
        return None

    try:
        data = json.loads(text)
        if isinstance(data, (dict, list)):
            return ParseResult(data=data, format="json")
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        data = ast.literal_eval(text)
        if isinstance(data, (dict, list, tuple)):
            return ParseResult(data=_convert_tuples(data), format="python_repr")
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        pass

    return None


def serialize(data: Any, fmt: str) -> str:
    """Serialize data back to the original format (JSON or Python repr)."""
    if fmt == "python_repr":
        return repr(data)
    return json.dumps(data)


def _convert_tuples(obj: Any) -> Any:
    """Recursively convert tuples to lists for JSON compatibility."""
    if isinstance(obj, tuple):
        return [_convert_tuples(item) for item in obj]
    elif isinstance(obj, list):
        return [_convert_tuples(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _convert_tuples(v) for k, v in obj.items()}
    return obj
