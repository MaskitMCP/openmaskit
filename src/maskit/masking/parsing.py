"""Utilities for parsing text that may be JSON or Python repr."""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ParseResult:
    data: Any
    format: str  # "json" | "python_repr"


def try_parse_structured(text: str) -> ParseResult | None:
    """Try JSON first, fall back to ast.literal_eval. Returns None if neither works."""
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
