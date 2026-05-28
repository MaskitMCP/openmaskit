"""In-memory buffer for traffic entries, drained periodically by a flush loop.

Mirrors the MaskingEngine `_pending_writes` + `_flush_loop` idiom: the proxy
hot path appends synchronously (microseconds), and a background task batches
writes to SQLite.
"""

from __future__ import annotations

import logging

from maskit.traffic.store import TrafficEntry, TrafficStore

logger = logging.getLogger(__name__)


class TrafficBuffer:
    """Single process-wide buffer for traffic entries across all targets."""

    def __init__(self) -> None:
        self._pending: list[TrafficEntry] = []

    def append(self, entry: TrafficEntry) -> None:
        self._pending.append(entry)

    def __len__(self) -> int:
        return len(self._pending)

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)

    async def flush(self, store: TrafficStore) -> int:
        """Drain pending entries into the store. Returns rows written."""
        if not self._pending:
            return 0
        batch = self._pending
        self._pending = []
        try:
            await store.insert_many(batch)
        except Exception:
            logger.exception("Failed to flush traffic buffer; dropping %d entries", len(batch))
            return 0
        return len(batch)
