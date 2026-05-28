"""SQLite persistence for traffic audit log.

Separate DB file from the masking store. Unmasked args/response are
Fernet-encrypted at rest using the shared TokenEncryption key.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import aiosqlite

from maskit.security import TokenEncryption

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    target_name   TEXT    NOT NULL,
    tool_name     TEXT,
    request_id    TEXT,
    status        TEXT    NOT NULL,
    duration_ms   INTEGER,
    args_enc      BLOB,
    response_enc  BLOB,
    masked_args   TEXT,
    masked_resp   TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_target_id ON traffic(target_name, id DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_id ON traffic(id DESC);
"""


@dataclass
class TrafficEntry:
    """A single traffic audit log entry.

    On insert: id is None (assigned by SQLite).
    On read: id is the row's primary key.

    The four content fields hold UTF-8 strings (typically JSON). The two
    `*_args` / `*_response` "unmasked" fields are stored encrypted; the
    masked variants are stored plaintext.
    """

    ts: float
    target_name: str
    status: str  # 'ok' | 'error' | 'blocked'
    id: int | None = None
    tool_name: str | None = None
    request_id: str | None = None
    duration_ms: int | None = None
    unmasked_args: str | None = None
    unmasked_response: str | None = None
    masked_args: str | None = None
    masked_response: str | None = None


class TrafficStore:
    """Async wrapper around the traffic SQLite database."""

    def __init__(self, db: aiosqlite.Connection, encryption: TokenEncryption):
        self._db = db
        self._enc = encryption

    @classmethod
    async def create(cls, path: str | Path) -> TrafficStore:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(_SCHEMA)
        await db.commit()
        return cls(db, TokenEncryption())

    async def close(self) -> None:
        await self._db.close()

    async def insert_many(self, entries: Iterable[TrafficEntry]) -> None:
        rows = []
        for e in entries:
            args_enc = (
                self._enc.encrypt_bytes(e.unmasked_args.encode())
                if e.unmasked_args is not None
                else None
            )
            resp_enc = (
                self._enc.encrypt_bytes(e.unmasked_response.encode())
                if e.unmasked_response is not None
                else None
            )
            rows.append(
                (
                    e.ts,
                    e.target_name,
                    e.tool_name,
                    e.request_id,
                    e.status,
                    e.duration_ms,
                    args_enc,
                    resp_enc,
                    e.masked_args,
                    e.masked_response,
                )
            )

        if not rows:
            return

        await self._db.executemany(
            """
            INSERT INTO traffic
              (ts, target_name, tool_name, request_id, status, duration_ms,
               args_enc, response_enc, masked_args, masked_resp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        await self._db.commit()

    async def query(
        self,
        target_name: str,
        limit: int = 50,
        before_id: int | None = None,
    ) -> list[TrafficEntry]:
        """Return entries for `target_name`, newest first.

        Use `before_id` for cursor pagination: pass the smallest id from
        the previous page to fetch the next older page.
        """
        if before_id is None:
            sql = """
                SELECT id, ts, target_name, tool_name, request_id, status,
                       duration_ms, args_enc, response_enc, masked_args, masked_resp
                FROM traffic
                WHERE target_name = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params: tuple = (target_name, limit)
        else:
            sql = """
                SELECT id, ts, target_name, tool_name, request_id, status,
                       duration_ms, args_enc, response_enc, masked_args, masked_resp
                FROM traffic
                WHERE target_name = ? AND id < ?
                ORDER BY id DESC
                LIMIT ?
            """
            params = (target_name, before_id, limit)

        out: list[TrafficEntry] = []
        async with self._db.execute(sql, params) as cursor:
            async for row in cursor:
                out.append(self._row_to_entry(row))
        return out

    async def enforce_row_cap(self, max_rows: int) -> int:
        """Delete oldest rows globally beyond `max_rows`. Returns rows deleted."""
        if max_rows <= 0:
            return 0
        cursor = await self._db.execute(
            """
            DELETE FROM traffic
            WHERE id < (
                SELECT id FROM traffic ORDER BY id DESC LIMIT 1 OFFSET ?
            )
            """,
            (max_rows - 1,),
        )
        deleted = cursor.rowcount or 0
        await self._db.commit()
        if deleted:
            logger.debug(f"Traffic row-cap rotation removed {deleted} rows")
        return deleted

    async def count(self) -> int:
        """Total row count (for tests / diagnostics)."""
        async with self._db.execute("SELECT COUNT(*) FROM traffic") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    def _row_to_entry(self, row: tuple) -> TrafficEntry:
        (
            id_,
            ts,
            target_name,
            tool_name,
            request_id,
            status,
            duration_ms,
            args_enc,
            resp_enc,
            masked_args,
            masked_resp,
        ) = row
        unmasked_args = (
            self._enc.decrypt_bytes(args_enc).decode() if args_enc is not None else None
        )
        unmasked_response = (
            self._enc.decrypt_bytes(resp_enc).decode() if resp_enc is not None else None
        )
        return TrafficEntry(
            id=id_,
            ts=ts,
            target_name=target_name,
            tool_name=tool_name,
            request_id=request_id,
            status=status,
            duration_ms=duration_ms,
            unmasked_args=unmasked_args,
            unmasked_response=unmasked_response,
            masked_args=masked_args,
            masked_response=masked_resp,
        )
