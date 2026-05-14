"""Logging configuration for Maskit with optional JSON formatting."""

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


def setup_logging() -> None:
    """Configure logging based on MASKIT_LOG_FORMAT environment variable.

    Supported formats:
    - "json": Structured JSON logs (for production log aggregation)
    - "text" (default): Human-readable text logs
    """
    log_format = os.getenv("MASKIT_LOG_FORMAT", "text").lower()

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
    root_logger.setLevel(logging.INFO)

    # Set debug level for specific modules
    logging.getLogger("mcp.client.auth").setLevel(logging.DEBUG)
    logging.getLogger("maskit.proxy.upstream").setLevel(logging.DEBUG)
