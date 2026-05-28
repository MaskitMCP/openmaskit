"""Tests for security utilities: validation and encryption."""

from __future__ import annotations

import pytest
from pathlib import Path

from openmaskit.security import (
    validate_server_id,
    TokenEncryption,
    read_token_file,
    write_token_file,
)


class TestValidateServerId:
    """Test server ID validation."""

    def test_valid_lowercase_alphanumeric(self):
        assert validate_server_id("postgres123") == "postgres123"

    def test_valid_with_hyphens(self):
        assert validate_server_id("my-server-123") == "my-server-123"

    def test_valid_with_underscores(self):
        assert validate_server_id("my_server_123") == "my_server_123"

    def test_valid_mixed(self):
        assert validate_server_id("postgres_prod-1") == "postgres_prod-1"

    def test_reject_uppercase(self):
        with pytest.raises(ValueError, match="lowercase"):
            validate_server_id("MyServer")

    def test_reject_path_traversal_dotdot(self):
        with pytest.raises(ValueError):
            validate_server_id("../etc/passwd")

    def test_reject_path_traversal_absolute(self):
        with pytest.raises(ValueError):
            validate_server_id("/etc/passwd")

    def test_reject_special_chars_at(self):
        with pytest.raises(ValueError):
            validate_server_id("server@example.com")

    def test_reject_special_chars_dot(self):
        with pytest.raises(ValueError):
            validate_server_id("my.server")

    def test_reject_too_long(self):
        with pytest.raises(ValueError):
            validate_server_id("a" * 65)

    def test_reject_empty(self):
        with pytest.raises(ValueError):
            validate_server_id("")

    def test_reject_spaces(self):
        with pytest.raises(ValueError):
            validate_server_id("my server")

    def test_max_length_accepted(self):
        # 64 chars is OK
        assert validate_server_id("a" * 64) == "a" * 64


class TestTokenEncryption:
    """Test OAuth token encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        enc = TokenEncryption()
        original = '{"access_token": "secret123", "refresh_token": "refresh456"}'

        encrypted = enc.encrypt(original)
        assert encrypted.startswith("ENCRYPTED:")
        assert "secret123" not in encrypted
        assert "refresh456" not in encrypted

        decrypted = enc.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_plaintext_for_migration(self):
        enc = TokenEncryption()
        plaintext = '{"tokens": {"access_token": "old"}}'

        # Should return as-is (no ENCRYPTED: prefix)
        result = enc.decrypt(plaintext)
        assert result == plaintext

    def test_file_read_write_with_encryption(self, tmp_path):
        token_path = tmp_path / "test.json"
        data = {
            "tokens": {
                "access_token": "secret123",
                "refresh_token": "refresh456"
            }
        }

        write_token_file(token_path, data)

        # File should be encrypted
        content = token_path.read_text()
        assert content.startswith("ENCRYPTED:")
        assert "secret123" not in content
        assert "refresh456" not in content

        # Read should decrypt
        loaded = read_token_file(token_path)
        assert loaded == data

    def test_auto_migration_from_plaintext(self, tmp_path):
        token_path = tmp_path / "plaintext.json"
        plaintext_data = '{"tokens": {"access_token": "old"}}'
        token_path.write_text(plaintext_data)

        # First read should migrate
        loaded = read_token_file(token_path)
        assert loaded["tokens"]["access_token"] == "old"

        # File should now be encrypted
        content = token_path.read_text()
        assert content.startswith("ENCRYPTED:")
        assert "old" not in content

    def test_key_generation(self, tmp_path, monkeypatch):
        key_path = tmp_path / ".key"
        monkeypatch.setattr("openmaskit.security.TokenEncryption._KEY_PATH", key_path)

        enc = TokenEncryption()
        enc._load_key()

        assert key_path.exists()
        assert oct(key_path.stat().st_mode)[-3:] == "600"

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_ENCRYPTION_KEY", "test-key-override")
        enc = TokenEncryption()

        key = enc._load_key()
        assert key == b"test-key-override"

    def test_nonexistent_file_returns_empty_dict(self, tmp_path):
        token_path = tmp_path / "nonexistent.json"
        result = read_token_file(token_path)
        assert result == {}

    def test_corrupted_file_returns_empty_dict(self, tmp_path):
        token_path = tmp_path / "corrupted.json"
        token_path.write_text("not valid json or encrypted data!!!")

        result = read_token_file(token_path)
        assert result == {}

    def test_file_permissions(self, tmp_path):
        token_path = tmp_path / "perms.json"
        data = {"tokens": {"access_token": "test"}}

        write_token_file(token_path, data)

        # Check permissions are 0o600
        mode = token_path.stat().st_mode
        assert oct(mode)[-3:] == "600"
