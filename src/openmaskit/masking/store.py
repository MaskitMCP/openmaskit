"""SQLite persistence for masking value mappings and rules."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from openmaskit.masking.mappers import ResponseMapper
from openmaskit.masking.rules import ArgumentGuardrail, ArgumentInjection, MaskingRule
from openmaskit.security import TokenEncryption

logger = logging.getLogger(__name__)


class ConfigDecryptionError(RuntimeError):
    """Raised when an mcp_servers config row cannot be decrypted.

    Indicates either a corrupted blob or a key mismatch. The caller should
    surface this — silently treating it as "no record" would hide the problem.
    """

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mappings (
    alias TEXT PRIMARY KEY,
    real_value TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    field_path TEXT NOT NULL,
    target_name TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    config_enc BLOB NOT NULL,
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
        self._alias_counters: dict[str, int] = {}
        # Server config columns are Fernet-encrypted at rest because they hold
        # user-supplied credentials (stdio env vars, HTTP static headers, OAuth
        # secrets). Same key file as OAuth token files.
        self._encryption = TokenEncryption()

    def _encrypt_config(self, config: dict) -> bytes:
        return self._encryption.encrypt_bytes(json.dumps(config).encode("utf-8"))

    def _decrypt_config(self, blob: bytes) -> dict:
        try:
            return json.loads(self._encryption.decrypt_bytes(blob).decode("utf-8"))
        except Exception as exc:
            raise ConfigDecryptionError(
                "Failed to decrypt mcp_servers config blob — either the row is "
                "corrupted or the encryption key has changed."
            ) from exc

    @classmethod
    async def create(cls, path: str | Path) -> MaskingStore:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
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

        await self._migrate_mcp_servers_encryption()

    async def _migrate_mcp_servers_encryption(self) -> None:
        """Migrate mcp_servers.config (plaintext JSON TEXT) to config_enc (BLOB).

        The on-disk plaintext column held user-supplied credentials (env vars,
        OAuth secrets, and now HTTP headers). Encrypt them in place and drop
        the plaintext column via the SQLite recreate-table dance.

        Idempotent: a no-op once config_enc exists and config does not.
        """
        cursor = await self._db.execute("PRAGMA table_info(mcp_servers)")
        cols = {row[1] for row in await cursor.fetchall()}
        if "config" not in cols:
            # Already migrated (or fresh install — _SCHEMA created the new table).
            return

        logger.info("Migrating mcp_servers.config → encrypted config_enc")

        # Read every row's plaintext config first; we'll encrypt as we copy.
        async with self._db.execute(
            "SELECT id, name, config, active, icon_url, installed_at FROM mcp_servers"
        ) as cur:
            old_rows = await cur.fetchall()

        # Recreate table dance: SQLite's ALTER TABLE DROP COLUMN is only
        # available on 3.35+ and we don't want to assume that.
        await self._db.executescript(
            """
            CREATE TABLE mcp_servers_new (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config_enc BLOB NOT NULL,
                active BOOLEAN NOT NULL DEFAULT 1,
                icon_url TEXT,
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        for row in old_rows:
            server_id, name, plaintext_config, active, icon_url, installed_at = row
            try:
                config = json.loads(plaintext_config) if plaintext_config else {}
            except (TypeError, ValueError):
                logger.warning(
                    "mcp_servers row %s has invalid JSON config; storing empty dict",
                    server_id,
                )
                config = {}
            blob = self._encrypt_config(config)
            await self._db.execute(
                "INSERT INTO mcp_servers_new "
                "(id, name, config_enc, active, icon_url, installed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (server_id, name, blob, active, icon_url, installed_at),
            )

        await self._db.execute("DROP TABLE mcp_servers")
        await self._db.execute("ALTER TABLE mcp_servers_new RENAME TO mcp_servers")
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_mcp_servers_active ON mcp_servers(active)"
        )
        await self._db.commit()
        logger.info("Migrated %d mcp_servers rows to encrypted storage", len(old_rows))

    async def _load_counters(self, target_name: str | None = None):
        """Load current max alias counters from existing mappings."""
        if target_name:
            query = "SELECT alias FROM mappings WHERE target_name = ?"
            params: tuple = (target_name,)
        else:
            query = "SELECT alias FROM mappings"
            params = ()

        async with self._db.execute(query, params) as cursor:
            async for (alias,) in cursor:
                parts = alias.rsplit("_", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    prefix = parts[0]
                    num = int(parts[1])
                    self._alias_counters[prefix] = max(
                        self._alias_counters.get(prefix, 0), num
                    )

    async def get_or_create_alias(
        self, real_value: str, tool_name: str, field_path: str, prefix: str, target_name: str = "default"
    ) -> str:
        """Get or create alias for a real value (handles concurrent requests)."""
        # Check existing first - this handles the common case after warmup
        async with self._db.execute(
            "SELECT alias FROM mappings WHERE real_value = ? AND field_path = ? AND target_name = ?",
            (real_value, field_path, target_name),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]

        # Create new alias - use retry loop to handle concurrent inserts
        # This is the standard pattern for handling races in optimistic concurrency
        for attempt in range(3):
            counter = self._alias_counters.get(prefix, 0) + 1
            self._alias_counters[prefix] = counter
            alias = f"{prefix}_{counter}"

            try:
                await self._db.execute(
                    "INSERT INTO mappings (alias, real_value, tool_name, field_path, target_name) VALUES (?, ?, ?, ?, ?)",
                    (alias, real_value, tool_name, field_path, target_name),
                )
                await self._db.commit()
                return alias
            except aiosqlite.IntegrityError:
                # Another coroutine created an alias for this value concurrently
                # Try to fetch it
                async with self._db.execute(
                    "SELECT alias FROM mappings WHERE real_value = ? AND field_path = ? AND target_name = ?",
                    (real_value, field_path, target_name),
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return row[0]
                # If still not found, retry with new counter
                if attempt < 2:
                    continue
                # Last attempt failed - raise
                raise

    async def resolve_alias(self, alias: str) -> str | None:
        """Look up the real value for an alias."""
        async with self._db.execute(
            "SELECT real_value FROM mappings WHERE alias = ?", (alias,)
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

    # --- Marketplace Servers ---

    async def install_server(self, server_id: str, name: str, config: dict, icon_url: str | None = None) -> None:
        blob = self._encrypt_config(config)
        await self._db.execute(
            "INSERT OR REPLACE INTO mcp_servers (id, name, config_enc, active, icon_url) VALUES (?, ?, ?, 1, ?)",
            (server_id, name, blob, icon_url),
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
        """Get all servers (active AND inactive) from database.

        `config` is returned as a JSON string (not a dict) to preserve the
        existing contract with /api/targets — the frontend does
        `JSON.parse(target.config)` on the value.
        """
        query = "SELECT id, name, config_enc, active, icon_url FROM mcp_servers ORDER BY name"
        async with self._db.execute(query) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "name": row[1],
                    "config": json.dumps(self._decrypt_config(row[2])),
                    "active": bool(row[3]),
                    "icon_url": row[4],
                }
                for row in rows
            ]

    async def update_server(self, server_id: str, name: str, config: dict) -> bool:
        blob = self._encrypt_config(config)
        cursor = await self._db.execute(
            "UPDATE mcp_servers SET name = ?, config_enc = ? WHERE id = ?",
            (name, blob, server_id),
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
        if active_only:
            query = "SELECT id, name, config_enc, active, icon_url, installed_at FROM mcp_servers WHERE active = 1"
        else:
            query = "SELECT id, name, config_enc, active, icon_url, installed_at FROM mcp_servers"

        async with self._db.execute(query) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "config": self._decrypt_config(r[2]),
                    "active": bool(r[3]),
                    "icon_url": r[4],
                    "installed_at": r[5],
                }
                for r in rows
            ]

    async def get_server(self, server_id: str) -> dict | None:
        async with self._db.execute(
            "SELECT id, name, config_enc, active, installed_at FROM mcp_servers WHERE id = ?",
            (server_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "name": row[1],
                "config": self._decrypt_config(row[2]),
                "active": bool(row[3]),
                "installed_at": row[4],
            }

    async def update_server_config(self, server_id: str, config: dict):
        """Update the config JSON for a server."""
        blob = self._encrypt_config(config)
        await self._db.execute(
            "UPDATE mcp_servers SET config_enc = ? WHERE id = ?",
            (blob, server_id),
        )
        await self._db.commit()

    async def close(self):
        await self._db.close()
