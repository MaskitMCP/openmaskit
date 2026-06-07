"""SQLite persistence for masking value mappings and rules."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from openmaskit.config_serde import dump_config, merge_update
from openmaskit.masking.mappers import ResponseMapper
from openmaskit.masking.rules import ArgumentGuardrail, ArgumentInjection, MaskingRule

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS mappings (
    target_name TEXT NOT NULL DEFAULT 'default',
    alias TEXT NOT NULL,
    real_value TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    field_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (target_name, alias)
);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    field_path TEXT NOT NULL,
    alias_prefix TEXT,
    active BOOLEAN NOT NULL DEFAULT 1,
    target_name TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS response_mappers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    mapper_type TEXT NOT NULL DEFAULT 'regex_replace',
    pattern TEXT NOT NULL,
    alias_prefix TEXT NOT NULL,
    "order" INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT 1,
    target_name TEXT NOT NULL DEFAULT 'default',
    config TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hidden_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    target_name TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tool_name, target_name)
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('marketplace', 'custom')),
    backend_id TEXT,
    config_json TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT 1,
    icon_url TEXT,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS guardrails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    argument_name TEXT NOT NULL DEFAULT '*',
    match_type TEXT NOT NULL DEFAULT 'contains',
    pattern TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT 'Blocked by guardrail',
    active BOOLEAN NOT NULL DEFAULT 1,
    target_name TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS injections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    argument_name TEXT NOT NULL,
    value TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'set',
    active BOOLEAN NOT NULL DEFAULT 1,
    target_name TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_active ON mcp_servers(active);
CREATE INDEX IF NOT EXISTS idx_mappings_real_value ON mappings(real_value);
CREATE INDEX IF NOT EXISTS idx_mappings_target ON mappings(target_name);
CREATE INDEX IF NOT EXISTS idx_rules_tool_name ON rules(tool_name);
CREATE INDEX IF NOT EXISTS idx_rules_target ON rules(target_name);
CREATE INDEX IF NOT EXISTS idx_response_mappers_tool ON response_mappers(tool_name);
CREATE INDEX IF NOT EXISTS idx_response_mappers_target ON response_mappers(target_name);
CREATE INDEX IF NOT EXISTS idx_hidden_tools_target ON hidden_tools(target_name);
CREATE INDEX IF NOT EXISTS idx_guardrails_tool ON guardrails(tool_name);
CREATE INDEX IF NOT EXISTS idx_guardrails_target ON guardrails(target_name);
CREATE INDEX IF NOT EXISTS idx_injections_tool ON injections(tool_name);
CREATE INDEX IF NOT EXISTS idx_injections_target ON injections(target_name);
"""


class MaskingStore:
    def __init__(self, db: aiosqlite.Connection):
        self._db = db
        # Per-target alias counter map: {target_name: {prefix: max_counter}}.
        # Scoping is required because aliases are unique per (target_name, alias),
        # not globally; two targets can independently hold "host_1" without
        # colliding.
        self._alias_counters: dict[str, dict[str, int]] = {}

    @classmethod
    async def create(cls, path: str | Path) -> MaskingStore:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
        # WAL + synchronous=NORMAL match traffic.db: the alias flush loop and
        # rule/mapper CRUD from the dashboard are concurrent writers, and
        # reads from the engine startup load happen alongside. Without WAL,
        # SQLite's default rollback journal serializes everything.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(_SCHEMA)
        await db.commit()
        store = cls(db)
        await store._migrate()
        await store._load_counters()
        return store

    async def _migrate(self):
        """Add columns to existing tables if missing."""
        cursor = await self._db.execute("PRAGMA table_info(mappings)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "target_name" not in columns:
            await self._db.execute(
                "ALTER TABLE mappings ADD COLUMN target_name TEXT NOT NULL DEFAULT 'default'"
            )
            await self._db.execute(
                "ALTER TABLE rules ADD COLUMN target_name TEXT NOT NULL DEFAULT 'default'"
            )
            await self._db.execute(
                "ALTER TABLE response_mappers ADD COLUMN target_name TEXT NOT NULL DEFAULT 'default'"
            )
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_mappings_target ON mappings(target_name)"
            )
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_rules_target ON rules(target_name)"
            )
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_response_mappers_target ON response_mappers(target_name)"
            )
            await self._db.commit()

        cursor = await self._db.execute("PRAGMA table_info(response_mappers)")
        mapper_columns = {row[1] for row in await cursor.fetchall()}
        if "config" not in mapper_columns:
            await self._db.execute(
                "ALTER TABLE response_mappers ADD COLUMN config TEXT DEFAULT NULL"
            )
            await self._db.commit()

        cursor = await self._db.execute("PRAGMA table_info(rules)")
        rule_columns = {row[1] for row in await cursor.fetchall()}
        if "action" not in rule_columns:
            await self._db.execute(
                "ALTER TABLE rules ADD COLUMN action TEXT NOT NULL DEFAULT 'mask'"
            )
            await self._db.commit()

        await self._migrate_mappings_pk()

    async def _migrate_mappings_pk(self) -> None:
        """Rebuild ``mappings`` with PK ``(target_name, alias)``.

        Old releases used ``alias`` alone as the PK, which meant two targets
        with overlapping alias_prefixes (e.g. both have a ``host`` rule) would
        collide at INSERT time and the second target's row would silently be
        rejected. After this migration each target has its own namespace for
        aliases.

        Idempotent: a no-op once the PK is already composite (or on a fresh
        install — ``_SCHEMA`` creates the new shape directly).
        """
        if await self._mappings_pk_is_composite():
            return

        logger.info("Migrating mappings to composite (target_name, alias) PK")
        await self._db.executescript(
            """
            CREATE TABLE mappings_new (
                target_name TEXT NOT NULL DEFAULT 'default',
                alias TEXT NOT NULL,
                real_value TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                field_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (target_name, alias)
            );
            """
        )
        # The old PK on `alias` guarantees uniqueness, so a direct copy can't
        # generate composite-PK duplicates.
        await self._db.execute(
            """
            INSERT INTO mappings_new
                (target_name, alias, real_value, tool_name, field_path, created_at)
            SELECT target_name, alias, real_value, tool_name, field_path, created_at
            FROM mappings
            """
        )
        await self._db.execute("DROP TABLE mappings")
        await self._db.execute("ALTER TABLE mappings_new RENAME TO mappings")
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_mappings_real_value ON mappings(real_value)"
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_mappings_target ON mappings(target_name)"
        )
        await self._db.commit()
        logger.info("Migration to composite mappings PK complete")

    async def _mappings_pk_is_composite(self) -> bool:
        cursor = await self._db.execute("PRAGMA table_info(mappings)")
        rows = await cursor.fetchall()
        # Each row is (cid, name, type, notnull, dflt_value, pk). pk > 0 means
        # the column participates in the PK.
        pk_cols = {row[1] for row in rows if row[5] > 0}
        return pk_cols == {"target_name", "alias"}

    async def _load_counters(self, target_name: str | None = None):
        """Load current max alias counters from existing mappings, per target."""
        if target_name:
            query = "SELECT target_name, alias FROM mappings WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT target_name, alias FROM mappings"
            params = ()

        async with self._db.execute(query, params) as cursor:
            async for (tname, alias) in cursor:
                parts = alias.rsplit("_", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    prefix = parts[0]
                    num = int(parts[1])
                    bucket = self._alias_counters.setdefault(tname, {})
                    bucket[prefix] = max(bucket.get(prefix, 0), num)

    async def get_or_create_alias(
        self, real_value: str, tool_name: str, field_path: str, prefix: str, target_name: str = "default"
    ) -> str:
        """Get or create alias for a real value, scoped to ``target_name``.

        The minted alias namespace is per-target: two targets can each hold
        ``host_1`` for different real values, and they don't see each other.
        """
        # Check existing first - this handles the common case after warmup
        async with self._db.execute(
            "SELECT alias FROM mappings WHERE real_value = ? AND field_path = ? AND target_name = ?",
            (real_value, field_path, target_name),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]

        bucket = self._alias_counters.setdefault(target_name, {})

        # Create new alias - use retry loop to handle concurrent inserts
        for attempt in range(3):
            counter = bucket.get(prefix, 0) + 1
            bucket[prefix] = counter
            alias = f"{prefix}_{counter}"

            try:
                await self._db.execute(
                    "INSERT INTO mappings (target_name, alias, real_value, tool_name, field_path) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (target_name, alias, real_value, tool_name, field_path),
                )
                await self._db.commit()
                return alias
            except aiosqlite.IntegrityError:
                # Another coroutine in the same target created this alias
                # concurrently; re-check by real_value.
                async with self._db.execute(
                    "SELECT alias FROM mappings WHERE real_value = ? AND field_path = ? AND target_name = ?",
                    (real_value, field_path, target_name),
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return row[0]
                if attempt < 2:
                    continue
                raise

    async def persist_alias(
        self,
        target_name: str,
        alias: str,
        real_value: str,
        tool_name: str,
        field_path: str,
    ) -> None:
        """Persist an engine-minted alias under ``(target_name, alias)``.

        Used by ``MaskingEngine.flush_pending`` to write back the alias the
        engine already returned to the caller. The engine's per-target counter
        is the authority for alias selection; the store just persists. ``INSERT
        OR IGNORE`` makes the call idempotent if the same pending row gets
        flushed twice (e.g. retry on shutdown).
        """
        await self._db.execute(
            "INSERT OR IGNORE INTO mappings "
            "(target_name, alias, real_value, tool_name, field_path) VALUES (?, ?, ?, ?, ?)",
            (target_name, alias, real_value, tool_name, field_path),
        )
        await self._db.commit()
        # Keep the store's counter in sync so a subsequent direct
        # ``get_or_create_alias`` call doesn't try to re-mint the same number.
        parts = alias.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit():
            prefix, num = parts[0], int(parts[1])
            bucket = self._alias_counters.setdefault(target_name, {})
            bucket[prefix] = max(bucket.get(prefix, 0), num)

    async def resolve_alias(
        self, alias: str, target_name: str | None = None
    ) -> str | None:
        """Look up the real value for an alias.

        When ``target_name`` is provided, the lookup is scoped to that target —
        the only correct mode now that aliases are unique per-target rather
        than globally. ``target_name=None`` falls back to "any target's row";
        kept for test ergonomics and for legacy callers that don't yet know
        which target they're in.
        """
        if target_name is not None:
            async with self._db.execute(
                "SELECT real_value FROM mappings WHERE alias = ? AND target_name = ?",
                (alias, target_name),
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None
        async with self._db.execute(
            "SELECT real_value FROM mappings WHERE alias = ? LIMIT 1", (alias,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def get_all_mappings(self, target_name: str | None = None) -> list[dict]:
        """Get all alias-to-value mappings."""
        if target_name:
            query = "SELECT alias, real_value, tool_name, field_path, created_at FROM mappings WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT alias, real_value, tool_name, field_path, created_at FROM mappings"
            params = ()

        async with self._db.execute(query, params) as cursor:
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

    async def get_all_aliases(self, target_name: str | None = None) -> dict[str, str]:
        """Get a dict of alias -> real_value for fast lookup."""
        if target_name:
            query = "SELECT alias, real_value FROM mappings WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT alias, real_value FROM mappings"
            params = ()

        async with self._db.execute(query, params) as cursor:
            return {row[0]: row[1] async for row in cursor}

    # --- Rule CRUD ---

    async def add_rule(self, rule: MaskingRule, target_name: str = "default") -> int:
        cursor = await self._db.execute(
            "INSERT INTO rules (tool_name, field_path, alias_prefix, action, active, target_name) VALUES (?, ?, ?, ?, ?, ?)",
            (rule.tool_name, rule.field_path, rule.alias_prefix, rule.action, rule.active, target_name),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_rules(self, target_name: str | None = None) -> list[MaskingRule]:
        if target_name:
            query = "SELECT id, tool_name, field_path, alias_prefix, action, active FROM rules WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT id, tool_name, field_path, alias_prefix, action, active FROM rules"
            params = ()

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [
                MaskingRule(
                    id=r[0],
                    tool_name=r[1],
                    field_path=r[2],
                    alias_prefix=r[3],
                    action=r[4] or "mask",
                    active=bool(r[5]),
                )
                for r in rows
            ]

    async def update_rule(self, rule_id: int, alias_prefix: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE rules SET alias_prefix = ? WHERE id = ?",
            (alias_prefix, rule_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def delete_rule(self, rule_id: int) -> bool:
        cursor = await self._db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        await self._db.commit()
        return cursor.rowcount > 0

    # --- Guardrail CRUD ---

    async def add_guardrail(self, guardrail: ArgumentGuardrail, target_name: str = "default") -> int:
        cursor = await self._db.execute(
            "INSERT INTO guardrails (tool_name, argument_name, match_type, pattern, message, active, target_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (guardrail.tool_name, guardrail.argument_name, guardrail.match_type, guardrail.pattern, guardrail.message, guardrail.active, target_name),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_guardrails(self, target_name: str | None = None) -> list[ArgumentGuardrail]:
        if target_name:
            query = "SELECT id, tool_name, argument_name, match_type, pattern, message, active FROM guardrails WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT id, tool_name, argument_name, match_type, pattern, message, active FROM guardrails"
            params = ()

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [
                ArgumentGuardrail(
                    id=r[0],
                    tool_name=r[1],
                    argument_name=r[2],
                    match_type=r[3],
                    pattern=r[4],
                    message=r[5],
                    active=bool(r[6]),
                )
                for r in rows
            ]

    async def update_guardrail(self, guardrail_id: int, **fields) -> bool:
        if not fields:
            return False
        allowed = {"tool_name", "argument_name", "match_type", "pattern", "message", "active"}

        # Build SET clauses and values list with explicit validation
        set_clauses = []
        values = []
        for k, v in fields.items():
            if k in allowed:
                set_clauses.append(f"{k} = ?")
                values.append(v)

        if not set_clauses:
            return False

        # Construct query with validated field names only
        query = f"UPDATE guardrails SET {', '.join(set_clauses)} WHERE id = ?"
        values.append(guardrail_id)

        cursor = await self._db.execute(query, values)
        await self._db.commit()
        return cursor.rowcount > 0

    async def delete_guardrail(self, guardrail_id: int) -> bool:
        cursor = await self._db.execute("DELETE FROM guardrails WHERE id = ?", (guardrail_id,))
        await self._db.commit()
        return cursor.rowcount > 0

    # --- Injection CRUD ---

    async def add_injection(self, injection: ArgumentInjection, target_name: str = "default") -> int:
        cursor = await self._db.execute(
            "INSERT INTO injections (tool_name, argument_name, value, mode, active, target_name) VALUES (?, ?, ?, ?, ?, ?)",
            (injection.tool_name, injection.argument_name, injection.value, injection.mode, injection.active, target_name),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_injections(self, target_name: str | None = None) -> list[ArgumentInjection]:
        if target_name:
            query = "SELECT id, tool_name, argument_name, value, mode, active FROM injections WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT id, tool_name, argument_name, value, mode, active FROM injections"
            params = ()

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [
                ArgumentInjection(
                    id=r[0],
                    tool_name=r[1],
                    argument_name=r[2],
                    value=r[3],
                    mode=r[4],
                    active=bool(r[5]),
                )
                for r in rows
            ]

    async def update_injection(self, injection_id: int, **fields) -> bool:
        if not fields:
            return False
        allowed = {"tool_name", "argument_name", "value", "mode", "active"}

        # Build SET clauses and values list with explicit validation
        set_clauses = []
        values = []
        for k, v in fields.items():
            if k in allowed:
                set_clauses.append(f"{k} = ?")
                values.append(v)

        if not set_clauses:
            return False

        # Construct query with validated field names only
        query = f"UPDATE injections SET {', '.join(set_clauses)} WHERE id = ?"
        values.append(injection_id)

        cursor = await self._db.execute(query, values)
        await self._db.commit()
        return cursor.rowcount > 0

    async def delete_injection(self, injection_id: int) -> bool:
        cursor = await self._db.execute("DELETE FROM injections WHERE id = ?", (injection_id,))
        await self._db.commit()
        return cursor.rowcount > 0

    # --- Mapper CRUD ---

    async def add_mapper(self, mapper: ResponseMapper, target_name: str = "default") -> int:
        if mapper.order == 0:
            async with self._db.execute(
                'SELECT COALESCE(MAX("order"), 0) FROM response_mappers WHERE tool_name = ? AND target_name = ?',
                (mapper.tool_name, target_name),
            ) as cursor:
                row = await cursor.fetchone()
                mapper.order = (row[0] if row else 0) + 1

        config_json = json.dumps(mapper.config) if mapper.config else None
        cursor = await self._db.execute(
            'INSERT INTO response_mappers (tool_name, mapper_type, pattern, alias_prefix, "order", active, target_name, config) '
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (mapper.tool_name, mapper.mapper_type, mapper.pattern, mapper.alias_prefix, mapper.order, mapper.active, target_name, config_json),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_mappers(self, target_name: str | None = None) -> list[ResponseMapper]:
        if target_name:
            query = 'SELECT id, tool_name, mapper_type, pattern, alias_prefix, "order", active, config FROM response_mappers WHERE target_name = ? ORDER BY "order"'
            params: tuple = (target_name,)
        else:
            query = 'SELECT id, tool_name, mapper_type, pattern, alias_prefix, "order", active, config FROM response_mappers ORDER BY "order"'
            params = ()

        async with self._db.execute(query, params) as cursor:
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
                    config=json.loads(r[7]) if r[7] else None,
                )
                for r in rows
            ]

    async def update_mapper(self, mapper_id: int, pattern: str, alias_prefix: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE response_mappers SET pattern = ?, alias_prefix = ? WHERE id = ?",
            (pattern, alias_prefix, mapper_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

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

    # --- Hidden Tools ---

    async def get_hidden_tools(self, target_name: str = "default") -> list[str]:
        async with self._db.execute(
            "SELECT tool_name FROM hidden_tools WHERE target_name = ?",
            (target_name,),
        ) as cursor:
            return [row[0] async for row in cursor]

    async def hide_tool(self, tool_name: str, target_name: str = "default") -> bool:
        cursor = await self._db.execute(
            "INSERT OR IGNORE INTO hidden_tools (tool_name, target_name) VALUES (?, ?)",
            (tool_name, target_name),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def unhide_tool(self, tool_name: str, target_name: str = "default") -> bool:
        cursor = await self._db.execute(
            "DELETE FROM hidden_tools WHERE tool_name = ? AND target_name = ?",
            (tool_name, target_name),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # --- MCP Servers ---
    #
    # All marketplace and custom HTTP/stdio servers persist here. The schema
    # carries source ('marketplace' | 'custom') and an optional backend_id
    # (catalog UUID for marketplace rows) so editing/gating logic doesn't have
    # to sniff for a backend_id inside the config dict to tell the two apart.
    #
    # On-disk shape: config_json is plaintext JSON with secrets inline-encrypted
    # via config_serde — see openmaskit/config_serde.py for the boundary
    # functions (dump_config / load_runtime_config / load_display_config /
    # merge_update). Callers receive the raw config_json string and pick the
    # right loader for their use case.

    async def install_server(
        self,
        server_id: str,
        name: str,
        source: str,
        backend_id: str | None,
        config: dict,
        icon_url: str | None = None,
    ) -> None:
        """Fresh install / reinstall — INSERT OR REPLACE.

        Used both for first-time install and for ``_finish_local_install``
        reauthorize-completion writes (full fresh config from the OAuth flow).
        Use ``update_server`` when you want preserve-on-absence merge semantics.
        """
        if source not in ("marketplace", "custom"):
            raise ValueError(f"Invalid source {source!r}")
        config_json = dump_config(config)
        await self._db.execute(
            "INSERT OR REPLACE INTO mcp_servers "
            "(id, name, source, backend_id, config_json, active, icon_url) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (server_id, name, source, backend_id, config_json, icon_url),
        )
        await self._db.commit()

    async def deactivate_server(self, server_id: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE mcp_servers SET active = 0 WHERE id = ?", (server_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def activate_server(self, server_id: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE mcp_servers SET active = 1 WHERE id = ?", (server_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def get_all_servers(self) -> list[dict]:
        """Get all servers (active AND inactive).

        Returns rows with raw ``config_json`` strings — callers pick
        ``load_runtime_config`` or ``load_display_config`` from
        ``openmaskit.config_serde``.
        """
        query = (
            "SELECT id, name, source, backend_id, config_json, active, icon_url "
            "FROM mcp_servers ORDER BY name"
        )
        async with self._db.execute(query) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "source": r[2],
                    "backend_id": r[3],
                    "config_json": r[4],
                    "active": bool(r[5]),
                    "icon_url": r[6],
                }
                for r in rows
            ]

    async def update_server(
        self, server_id: str, name: str, incoming_config: dict
    ) -> bool:
        """Update a server's name + config with preserve-on-absence merge.

        Secret fields the caller omitted, sent as empty, or sent as the
        redaction sentinel are kept from storage (still encrypted). Used by
        the Edit modal so users don't have to re-type every secret on every
        edit. For full-replace writes (e.g. OAuth reauthorize completion),
        call ``install_server`` instead.
        """
        async with self._db.execute(
            "SELECT config_json FROM mcp_servers WHERE id = ?", (server_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return False
        merged = merge_update(row[0], incoming_config)
        config_json = dump_config(merged)
        cursor = await self._db.execute(
            "UPDATE mcp_servers SET name = ?, config_json = ? WHERE id = ?",
            (name, config_json, server_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def uninstall_server(self, server_id: str) -> bool:
        cursor = await self._db.execute(
            "DELETE FROM mcp_servers WHERE id = ?", (server_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def get_installed_servers(self, active_only: bool = False) -> list[dict]:
        """Get installed servers. Used by startup reconnect + marketplace
        catalog enrichment.

        Returns rows with raw ``config_json`` strings — see ``get_all_servers``.
        """
        if active_only:
            query = (
                "SELECT id, name, source, backend_id, config_json, active, icon_url, installed_at "
                "FROM mcp_servers WHERE active = 1"
            )
        else:
            query = (
                "SELECT id, name, source, backend_id, config_json, active, icon_url, installed_at "
                "FROM mcp_servers"
            )

        async with self._db.execute(query) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "source": r[2],
                    "backend_id": r[3],
                    "config_json": r[4],
                    "active": bool(r[5]),
                    "icon_url": r[6],
                    "installed_at": r[7],
                }
                for r in rows
            ]

    async def get_server(self, server_id: str) -> dict | None:
        """Get a single server row.

        Returns the row with raw ``config_json`` — see ``get_all_servers``.
        """
        async with self._db.execute(
            "SELECT id, name, source, backend_id, config_json, active, icon_url, installed_at "
            "FROM mcp_servers WHERE id = ?",
            (server_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "name": row[1],
                "source": row[2],
                "backend_id": row[3],
                "config_json": row[4],
                "active": bool(row[5]),
                "icon_url": row[6],
                "installed_at": row[7],
            }

    async def update_server_config(self, server_id: str, config: dict) -> None:
        """Replace a server's config verbatim (no merge).

        For flows that build the full intended config server-side
        (marketplace user_args reconfigure). Use ``update_server`` when
        applying user edits that may omit unchanged secrets.
        """
        config_json = dump_config(config)
        await self._db.execute(
            "UPDATE mcp_servers SET config_json = ? WHERE id = ?",
            (config_json, server_id),
        )
        await self._db.commit()

    async def close(self):
        await self._db.close()
