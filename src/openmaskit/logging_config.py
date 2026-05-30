"""Logging configuration for OpenMaskit with optional JSON formatting."""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "target_name"):
            log_data["target_name"] = record.target_name
        if hasattr(record, "tool_name"):
            log_data["tool_name"] = record.tool_name

        return json.dumps(log_data)


_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def resolve_log_level(value: str | None) -> int:
    """Resolve a user-supplied level string to a logging constant.

    Unknown values fall back to INFO so a typo never silences logging
    entirely or floods the console.
    """
    if not value:
        return logging.INFO
    normalized = value.strip().upper()
    if normalized in _VALID_LEVELS:
        return getattr(logging, normalized)
    return logging.INFO


def setup_logging() -> None:
    """Configure logging based on OPENMASKIT_LOG_* environment variables.

    OPENMASKIT_LOG_LEVEL — DEBUG / INFO (default) / WARNING / ERROR.
    OPENMASKIT_LOG_FORMAT — "json" for structured logs, "text" (default) otherwise.
    """
    log_format = os.getenv("OPENMASKIT_LOG_FORMAT", "text").lower()
    log_level = resolve_log_level(os.getenv("OPENMASKIT_LOG_LEVEL"))

    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
        )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)
