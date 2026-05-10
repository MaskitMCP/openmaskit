"""SQLite persistence for masking value mappings and rules."""

from __future__ import annotations

import os
from pathlib import Path

import aiosqlite

from maskit.masking.mappers import ResponseMapper
from maskit.masking.rules import MaskingRule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mappings (
    alias TEXT PRIMARY KEY,
    real_value TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    field_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    field_path TEXT NOT NULL,
    alias_prefix TEXT,
    active BOOLEAN NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS response_mappers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    mapper_type TEXT NOT NULL DEFAULT 'regex_replace',
    pattern TEXT NOT NULL,
    alias_prefix TEXT NOT NULL,
    "order" INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mappings_real_value ON mappings(real_value);
CREATE INDEX IF NOT EXISTS idx_rules_tool_name ON rules(tool_name);
CREATE INDEX IF NOT EXISTS idx_response_mappers_tool ON response_mappers(tool_name);
"""


class MaskingStore:
    def __init__(self, db: aiosqlite.Connection):
        self._db = db
        self._alias_counters: dict[str, int] = {}

    @classmethod
    async def create(cls, path: str | Path) -> MaskingStore:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
        await db.executescript(_SCHEMA)
        await db.commit()
        store = cls(db)
        await store._load_counters()
        return store

    async def _load_counters(self):
        """Load current max alias counters from existing mappings."""
        async with self._db.execute(
            "SELECT alias FROM mappings"
        ) as cursor:
            async for (alias,) in cursor:
                parts = alias.rsplit("_", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    prefix = parts[0]
                    num = int(parts[1])
                    self._alias_counters[prefix] = max(
                        self._alias_counters.get(prefix, 0), num
                    )

    async def get_or_create_alias(
        self, real_value: str, tool_name: str, field_path: str, prefix: str
    ) -> str:
        """Get existing alias for a real value, or create a new one."""
        async with self._db.execute(
            "SELECT alias FROM mappings WHERE real_value = ? AND field_path = ?",
            (real_value, field_path),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]

        # Create new alias
        counter = self._alias_counters.get(prefix, 0) + 1
        self._alias_counters[prefix] = counter
        alias = f"{prefix}_{counter}"

        await self._db.execute(
            "INSERT INTO mappings (alias, real_value, tool_name, field_path) VALUES (?, ?, ?, ?)",
            (alias, real_value, tool_name, field_path),
        )
        await self._db.commit()
        return alias

    async def resolve_alias(self, alias: str) -> str | None:
        """Look up the real value for an alias."""
        async with self._db.execute(
            "SELECT real_value FROM mappings WHERE alias = ?", (alias,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def get_all_mappings(self) -> list[dict]:
        """Get all alias-to-value mappings."""
        async with self._db.execute(
            "SELECT alias, real_value, tool_name, field_path, created_at FROM mappings"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "alias": r[0],
                    "real_value": r[1],
                    "tool_name": r[2],
                    "field_path": r[3],
                    "created_at": r[4],
                }
                for r in rows
            ]

    async def get_all_aliases(self) -> dict[str, str]:
        """Get a dict of alias -> real_value for fast lookup."""
        async with self._db.execute(
            "SELECT alias, real_value FROM mappings"
        ) as cursor:
            return {row[0]: row[1] async for row in cursor}

    # --- Rule CRUD ---

    async def add_rule(self, rule: MaskingRule) -> int:
        cursor = await self._db.execute(
            "INSERT INTO rules (tool_name, field_path, alias_prefix, active) VALUES (?, ?, ?, ?)",
            (rule.tool_name, rule.field_path, rule.alias_prefix, rule.active),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_rules(self) -> list[MaskingRule]:
        async with self._db.execute(
            "SELECT id, tool_name, field_path, alias_prefix, active FROM rules"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                MaskingRule(
                    id=r[0],
                    tool_name=r[1],
                    field_path=r[2],
                    alias_prefix=r[3],
                    active=bool(r[4]),
                )
                for r in rows
            ]

    async def delete_rule(self, rule_id: int) -> bool:
        cursor = await self._db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        await self._db.commit()
        return cursor.rowcount > 0

    # --- Mapper CRUD ---

    async def add_mapper(self, mapper: ResponseMapper) -> int:
        if mapper.order == 0:
            async with self._db.execute(
                'SELECT COALESCE(MAX("order"), 0) FROM response_mappers WHERE tool_name = ?',
                (mapper.tool_name,),
            ) as cursor:
                row = await cursor.fetchone()
                mapper.order = (row[0] if row else 0) + 1

        cursor = await self._db.execute(
            'INSERT INTO response_mappers (tool_name, mapper_type, pattern, alias_prefix, "order", active) '
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mapper.tool_name, mapper.mapper_type, mapper.pattern, mapper.alias_prefix, mapper.order, mapper.active),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_mappers(self) -> list[ResponseMapper]:
        async with self._db.execute(
            'SELECT id, tool_name, mapper_type, pattern, alias_prefix, "order", active FROM response_mappers ORDER BY "order"'
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                ResponseMapper(
                    id=r[0],
                    tool_name=r[1],
                    mapper_type=r[2],
                    pattern=r[3],
                    alias_prefix=r[4],
                    order=r[5],
                    active=bool(r[6]),
                )
                for r in rows
            ]

    async def delete_mapper(self, mapper_id: int) -> bool:
        cursor = await self._db.execute("DELETE FROM response_mappers WHERE id = ?", (mapper_id,))
        await self._db.commit()
        return cursor.rowcount > 0

    async def reorder_mappers(self, mapper_ids: list[int]) -> None:
        for idx, mapper_id in enumerate(mapper_ids):
            await self._db.execute(
                'UPDATE response_mappers SET "order" = ? WHERE id = ?',
                (idx, mapper_id),
            )
        await self._db.commit()

    async def close(self):
        await self._db.close()
