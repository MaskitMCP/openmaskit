"""Tests for at-rest Fernet encryption of mcp_servers.config_enc.

The config column holds user-supplied credentials (stdio env vars, OAuth
client_secrets, custom HTTP headers). It must be encrypted on disk, decrypted
transparently by the store, fail loudly on corruption / key mismatch, and
migrate cleanly from the pre-encryption plaintext schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
import pytest
import pytest_asyncio

from openmaskit.masking.store import ConfigDecryptionError, MaskingStore


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


class TestEncryptionAtRest:
    @pytest.mark.anyio
    async def test_install_server_persists_encrypted_blob(self, store, tmp_path):
        # A config containing strings any test reader can grep for.
        secret = "DD-API-KEY-SUPERSECRET-DEADBEEF"
        await store.install_server(
            "datadog",
            "Datadog",
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"DD-API-KEY": secret},
            },
        )

        # Read the raw blob bypassing the store's decryption path.
        async with store._db.execute(
            "SELECT config_enc FROM mcp_servers WHERE id = ?", ("datadog",)
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        blob = row[0]
        assert isinstance(blob, bytes)
        # The Fernet ciphertext must not contain the plaintext secret anywhere.
        assert secret.encode() not in blob
        assert b"DD-API-KEY" not in blob
        assert b"transport" not in blob

    @pytest.mark.anyio
    async def test_get_server_returns_decrypted_dict(self, store):
        config = {
            "transport": "http",
            "url": "https://example.com/mcp",
            "headers": {"DD-API-KEY": "abc"},
        }
        await store.install_server("datadog", "Datadog", config)
        record = await store.get_server("datadog")
        assert record is not None
        assert record["config"] == config

    @pytest.mark.anyio
    async def test_get_installed_servers_returns_decrypted_dicts(self, store):
        config = {"transport": "stdio", "command": "uvx", "env": {"K": "v"}}
        await store.install_server("local", "Local", config)
        rows = await store.get_installed_servers()
        assert len(rows) == 1
        assert rows[0]["config"] == config

    @pytest.mark.anyio
    async def test_get_all_servers_returns_decrypted_json_string(self, store):
        """/api/targets contract: config is a JSON-string so the frontend can
        JSON.parse() it. The decryption happens here; the wire shape stays the
        same as before.
        """
        config = {"transport": "stdio", "command": "uvx"}
        await store.install_server("local", "Local", config)
        rows = await store.get_all_servers()
        assert len(rows) == 1
        assert isinstance(rows[0]["config"], str)
        assert json.loads(rows[0]["config"]) == config

    @pytest.mark.anyio
    async def test_update_server_re_encrypts(self, store):
        await store.install_server(
            "x", "X", {"transport": "stdio", "command": "old"}
        )
        async with store._db.execute(
            "SELECT config_enc FROM mcp_servers WHERE id = ?", ("x",)
        ) as cur:
            old_blob = (await cur.fetchone())[0]

        await store.update_server(
            "x", "X", {"transport": "stdio", "command": "new", "args": ["a"]}
        )

        async with store._db.execute(
            "SELECT config_enc FROM mcp_servers WHERE id = ?", ("x",)
        ) as cur:
            new_blob = (await cur.fetchone())[0]
        assert new_blob != old_blob

        record = await store.get_server("x")
        assert record["config"]["command"] == "new"
        assert record["config"]["args"] == ["a"]

    @pytest.mark.anyio
    async def test_update_server_config_re_encrypts(self, store):
        """The lower-level update_server_config (used by hot reconfig paths)
        also writes through the encryption helper.
        """
        await store.install_server(
            "x", "X", {"transport": "stdio", "command": "old"}
        )
        await store.update_server_config(
            "x", {"transport": "stdio", "command": "new"}
        )
        record = await store.get_server("x")
        assert record["config"]["command"] == "new"

    @pytest.mark.anyio
    async def test_corrupt_blob_raises_configdecryption_error(self, store):
        await store.install_server(
            "x", "X", {"transport": "stdio", "command": "uvx"}
        )
        # Tamper with the blob: flip enough bytes that Fernet's HMAC rejects it.
        await store._db.execute(
            "UPDATE mcp_servers SET config_enc = ? WHERE id = ?",
            (b"not-a-real-fernet-token", "x"),
        )
        await store._db.commit()

        with pytest.raises(ConfigDecryptionError):
            await store.get_server("x")

    @pytest.mark.anyio
    async def test_get_server_missing_returns_none_not_error(self, store):
        # Distinguish "no row" from "decryption failed". Encryption is only
        # consulted when there is a row to decrypt.
        assert await store.get_server("nonexistent") is None


class TestMigrationFromPlaintextColumn:
    """The migration runs inside MaskingStore.create — _SCHEMA's
    `CREATE TABLE IF NOT EXISTS` is a no-op when the table exists with the old
    columns, so _migrate must detect & rewrite the table.
    """

    @pytest.mark.anyio
    async def test_existing_plaintext_rows_get_encrypted_and_round_trip(
        self, tmp_path
    ):
        db_path = tmp_path / "legacy.db"

        # Build a database with the OLD schema (config TEXT) and seed a row.
        legacy_db = await aiosqlite.connect(str(db_path))
        await legacy_db.executescript(
            """
            CREATE TABLE mcp_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config TEXT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT 1,
                icon_url TEXT,
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        plaintext_config = json.dumps(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"DD-API-KEY": "MIGRATED-SECRET"},
            }
        )
        await legacy_db.execute(
            "INSERT INTO mcp_servers (id, name, config, active, icon_url) "
            "VALUES (?, ?, ?, ?, ?)",
            ("legacy", "Legacy", plaintext_config, 1, None),
        )
        await legacy_db.commit()
        await legacy_db.close()

        # Open through the store — migration runs in MaskingStore.create.
        store = await MaskingStore.create(db_path)
        try:
            # Public surface returns the same dict the legacy row stored.
            record = await store.get_server("legacy")
            assert record is not None
            assert record["config"]["headers"]["DD-API-KEY"] == "MIGRATED-SECRET"

            # Old `config` column is gone; new `config_enc` BLOB is present.
            async with store._db.execute("PRAGMA table_info(mcp_servers)") as cur:
                cols = {row[1]: row[2] for row in await cur.fetchall()}
            assert "config" not in cols
            assert "config_enc" in cols

            # The on-disk blob no longer contains the plaintext secret.
            async with store._db.execute(
                "SELECT config_enc FROM mcp_servers WHERE id = ?", ("legacy",)
            ) as cur:
                blob = (await cur.fetchone())[0]
            assert isinstance(blob, bytes)
            assert b"MIGRATED-SECRET" not in blob
        finally:
            await store.close()

    @pytest.mark.anyio
    async def test_migration_is_idempotent(self, tmp_path):
        """Opening the same DB twice doesn't re-migrate or lose data."""
        db_path = tmp_path / "twice.db"

        store1 = await MaskingStore.create(db_path)
        await store1.install_server(
            "x", "X", {"transport": "stdio", "command": "uvx"}
        )
        await store1.close()

        store2 = await MaskingStore.create(db_path)
        try:
            record = await store2.get_server("x")
            assert record is not None
            assert record["config"]["command"] == "uvx"
        finally:
            await store2.close()

    @pytest.mark.anyio
    async def test_migration_skips_when_table_already_new(self, tmp_path):
        """Fresh installs hit _SCHEMA's new shape — _migrate must be a no-op
        on tables that never had the `config` column.
        """
        store = await MaskingStore.create(tmp_path / "fresh.db")
        try:
            async with store._db.execute("PRAGMA table_info(mcp_servers)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            assert cols == {
                "id",
                "name",
                "config_enc",
                "active",
                "icon_url",
                "installed_at",
            }
        finally:
            await store.close()

    @pytest.mark.anyio
    async def test_migration_tolerates_invalid_json_row(self, tmp_path):
        """A legacy row with non-JSON content shouldn't poison the migration —
        store an empty dict and log, so the rest of the table can still
        decrypt cleanly.
        """
        db_path = tmp_path / "bad.db"
        legacy_db = await aiosqlite.connect(str(db_path))
        await legacy_db.executescript(
            """
            CREATE TABLE mcp_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config TEXT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT 1,
                icon_url TEXT,
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        await legacy_db.execute(
            "INSERT INTO mcp_servers (id, name, config, active) VALUES (?, ?, ?, ?)",
            ("bad", "Bad", "not-valid-json{", 1),
        )
        await legacy_db.commit()
        await legacy_db.close()

        store = await MaskingStore.create(db_path)
        try:
            record = await store.get_server("bad")
            assert record is not None
            assert record["config"] == {}
        finally:
            await store.close()
