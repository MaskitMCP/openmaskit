"""Tests for proxy upstream connections."""

import json
from pathlib import Path

import pytest
import pytest_asyncio

from maskit.security import read_token_file
from maskit.proxy.upstream import (
    _is_self_managed_oauth,
    _load_backend_oauth_token,
    _load_backend_oauth_tokens,
    _save_backend_oauth_tokens,
    is_oauth_token_expired,
    refresh_backend_oauth_token,
)


class TestOAuthTokenLoading:
    """Test OAuth token loading from backend-managed files."""

    @pytest.mark.anyio
    async def test_load_backend_oauth_token_success(self, tmp_path):
        """Load access token successfully from token file."""
        # Create OAuth token file
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test-server.json"

        token_data = {
            "tokens": {
                "access_token": "eyJhbGc...",
                "refresh_token": "refresh_abc",
                "expires_in": 3600,
            }
        }
        token_file.write_text(json.dumps(token_data))

        # Test loading
        store_path = tmp_path / "store.db"
        token = _load_backend_oauth_token("test-server", str(store_path))

        assert token == "eyJhbGc..."

    @pytest.mark.anyio
    async def test_load_backend_oauth_token_missing_file(self, tmp_path):
        """Return None when token file doesn't exist."""
        store_path = tmp_path / "store.db"
        token = _load_backend_oauth_token("nonexistent-server", str(store_path))

        assert token is None

    @pytest.mark.anyio
    async def test_load_backend_oauth_token_invalid_server_id(self, tmp_path):
        """Handle invalid server ID safely."""
        store_path = tmp_path / "store.db"
        # Server IDs with path traversal attempts should fail
        token = _load_backend_oauth_token("../../../etc/passwd", str(store_path))

        assert token is None

    @pytest.mark.anyio
    async def test_load_backend_oauth_token_malformed_json(self, tmp_path):
        """Handle malformed JSON token file."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test-server.json"
        token_file.write_text("not valid json")

        store_path = tmp_path / "store.db"
        token = _load_backend_oauth_token("test-server", str(store_path))

        assert token is None

    @pytest.mark.anyio
    async def test_load_backend_oauth_token_missing_access_token(self, tmp_path):
        """Handle token file without access_token field."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test-server.json"

        # Missing access_token in tokens dict
        token_data = {
            "tokens": {
                "refresh_token": "refresh_only"
            }
        }
        token_file.write_text(json.dumps(token_data))

        store_path = tmp_path / "store.db"
        token = _load_backend_oauth_token("test-server", str(store_path))

        assert token is None

    @pytest.mark.anyio
    async def test_load_backend_oauth_tokens_success(self, tmp_path):
        """Load full token dict successfully."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "github.json"

        token_data = {
            "tokens": {
                "access_token": "gho_abc123",
                "refresh_token": "refresh_xyz",
                "token_type": "Bearer",
                "expires_in": 7200,
            }
        }
        token_file.write_text(json.dumps(token_data))

        store_path = tmp_path / "store.db"
        tokens = _load_backend_oauth_tokens("github", str(store_path))

        assert tokens is not None
        assert tokens["access_token"] == "gho_abc123"
        assert tokens["refresh_token"] == "refresh_xyz"
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 7200

    @pytest.mark.anyio
    async def test_load_backend_oauth_tokens_missing_file(self, tmp_path):
        """Return empty dict when token file doesn't exist."""
        store_path = tmp_path / "store.db"
        tokens = _load_backend_oauth_tokens("missing", str(store_path))

        assert tokens == {}

    @pytest.mark.anyio
    async def test_load_backend_oauth_tokens_empty_tokens(self, tmp_path):
        """Handle token file with empty tokens dict."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test.json"

        token_data = {"tokens": {}}
        token_file.write_text(json.dumps(token_data))

        store_path = tmp_path / "store.db"
        tokens = _load_backend_oauth_tokens("test", str(store_path))

        assert tokens == {}

    @pytest.mark.anyio
    async def test_save_backend_oauth_tokens_creates_directory(self, tmp_path):
        """Create OAuth directory if it doesn't exist."""
        store_path = tmp_path / "store.db"

        tokens = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
        }

        _save_backend_oauth_tokens("new-server", str(store_path), tokens)

        # Verify directory and file were created
        oauth_dir = tmp_path / "oauth"
        assert oauth_dir.exists()

        token_file = oauth_dir / "new-server.json"
        assert token_file.exists()

        # Verify content
        saved_data = read_token_file(token_file)
        assert saved_data["tokens"]["access_token"] == "new_token"
        assert saved_data["tokens"]["refresh_token"] == "new_refresh"

    @pytest.mark.anyio
    async def test_save_backend_oauth_tokens_overwrites_existing(self, tmp_path):
        """Overwrite existing token file."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test.json"

        # Write old tokens
        old_data = {"tokens": {"access_token": "old_token"}}
        token_file.write_text(json.dumps(old_data))

        # Save new tokens
        store_path = tmp_path / "store.db"
        new_tokens = {"access_token": "updated_token", "refresh_token": "updated_refresh"}
        _save_backend_oauth_tokens("test", str(store_path), new_tokens)

        # Verify overwrite
        saved_data = read_token_file(token_file)
        assert saved_data["tokens"]["access_token"] == "updated_token"
        assert saved_data["tokens"]["refresh_token"] == "updated_refresh"

    @pytest.mark.anyio
    async def test_save_backend_oauth_tokens_invalid_server_id(self, tmp_path):
        """Reject invalid server IDs."""
        store_path = tmp_path / "store.db"
        tokens = {"access_token": "token"}

        # Should raise or handle safely
        try:
            _save_backend_oauth_tokens("../../../etc/passwd", str(store_path), tokens)
            # If it doesn't raise, at least verify it didn't create the file
            passwd_file = tmp_path / "oauth" / ".." / ".." / ".." / "etc" / "passwd.json"
            assert not passwd_file.exists()
        except (ValueError, OSError):
            # Expected to fail with path traversal
            pass

    @pytest.mark.anyio
    async def test_save_backend_oauth_tokens_preserves_metadata(self, tmp_path):
        """Preserve metadata when updating tokens."""
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_file = oauth_dir / "test.json"

        # Write initial data with metadata
        initial_data = {
            "tokens": {"access_token": "old"},
            "metadata": {"created_at": "2024-01-01", "server_name": "Test Server"}
        }
        token_file.write_text(json.dumps(initial_data))

        # Update tokens
        store_path = tmp_path / "store.db"
        new_tokens = {"access_token": "new_token"}
        _save_backend_oauth_tokens("test", str(store_path), new_tokens)

        # Verify metadata preserved
        saved_data = read_token_file(token_file)
        assert saved_data["tokens"]["access_token"] == "new_token"
        assert saved_data.get("metadata", {}).get("created_at") == "2024-01-01"
        assert saved_data.get("metadata", {}).get("server_name") == "Test Server"


class TestUpstreamConfigParsing:
    """Test parsing of upstream configuration."""

    def test_stdio_config_basic(self):
        """Parse basic stdio configuration."""
        from maskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "stdio",
            "command": "uvx",
            "args": ["mcp-server-time"],
        }

        upstream = _build_upstream_config(config)

        assert upstream.command == "uvx"
        assert upstream.args == ["mcp-server-time"]
        assert upstream.env == {}

    def test_stdio_config_with_env(self):
        """Parse stdio configuration with environment variables."""
        from maskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "stdio",
            "command": "python",
            "args": ["-m", "my_server"],
            "env": {"DEBUG": "1", "API_KEY": "secret"},
        }

        upstream = _build_upstream_config(config)

        assert upstream.command == "python"
        assert upstream.args == ["-m", "my_server"]
        assert upstream.env == {"DEBUG": "1", "API_KEY": "secret"}

    def test_stdio_config_with_user_args(self):
        """Parse stdio configuration with user-provided arguments."""
        from maskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "stdio",
            "command": "mcp-server",
            "args": ["--base-arg"],
            "meta": {
                "user_args": {
                    "data_dir": {
                        "arg_format": "--data-dir {value}",
                        "values": ["/custom/path"]
                    },
                    "port": {
                        "arg_format": "--port {value}",
                        "values": ["8080"]
                    }
                }
            }
        }

        upstream = _build_upstream_config(config)

        assert upstream.command == "mcp-server"
        # Base args + user args
        assert "--base-arg" in upstream.args
        assert "--data-dir" in upstream.args
        assert "/custom/path" in upstream.args
        assert "--port" in upstream.args
        assert "8080" in upstream.args

    def test_http_config_basic(self):
        """Parse basic HTTP configuration."""
        from maskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "http",
            "url": "https://mcp.example.com/mcp",
        }

        upstream = _build_upstream_config(config)

        assert upstream.url == "https://mcp.example.com/mcp"
        assert upstream.oauth is None

    def test_http_config_with_oauth(self):
        """Parse HTTP configuration with OAuth."""
        from maskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "http",
            "url": "https://mcp.slack.com/mcp",
            "oauth": {
                "client_id": "slack-client-id",
                "scopes": ["channels:read", "chat:write"]
            }
        }

        upstream = _build_upstream_config(config)

        assert upstream.url == "https://mcp.slack.com/mcp"
        assert upstream.oauth is not None
        assert upstream.oauth.client_id == "slack-client-id"
        assert "channels:read" in upstream.oauth.scopes

    def test_merge_user_args_single_value(self):
        """Merge user args with single value."""
        from maskit.proxy.manager import _merge_user_args

        base_args = ["--base"]
        config = {
            "meta": {
                "user_args": {
                    "config": {
                        "arg_format": "--config {value}",
                        "values": ["/path/to/config.yml"]
                    }
                }
            }
        }

        result = _merge_user_args(base_args, config)

        assert result == ["--base", "--config", "/path/to/config.yml"]

    def test_merge_user_args_multiple_values(self):
        """Merge user args with multiple values."""
        from maskit.proxy.manager import _merge_user_args

        base_args = []
        config = {
            "meta": {
                "user_args": {
                    "tag": {
                        "arg_format": "--tag {value}",
                        "values": ["production", "critical", "monitored"]
                    }
                }
            }
        }

        result = _merge_user_args(base_args, config)

        assert "--tag" in result
        assert "production" in result
        assert "critical" in result
        assert "monitored" in result

    def test_merge_user_args_empty_meta(self):
        """Handle config without meta.user_args."""
        from maskit.proxy.manager import _merge_user_args

        base_args = ["--existing"]
        config = {}

        result = _merge_user_args(base_args, config)

        assert result == ["--existing"]

    def test_merge_user_args_missing_arg_format(self):
        """Skip user args without arg_format."""
        from maskit.proxy.manager import _merge_user_args

        base_args = ["--base"]
        config = {
            "meta": {
                "user_args": {
                    "broken": {
                        "values": ["value"]
                        # Missing arg_format
                    }
                }
            }
        }

        result = _merge_user_args(base_args, config)

        # Should skip the broken arg and just return base
        assert result == ["--base"]

    def test_merge_user_args_preserves_order(self):
        """Preserve base args order and append user args."""
        from maskit.proxy.manager import _merge_user_args

        base_args = ["cmd", "--flag1", "val1", "--flag2"]
        config = {
            "meta": {
                "user_args": {
                    "extra": {
                        "arg_format": "--extra {value}",
                        "values": ["added"]
                    }
                }
            }
        }

        result = _merge_user_args(base_args, config)

        # Base args first, then user args
        assert result[:4] == ["cmd", "--flag1", "val1", "--flag2"]
        assert "--extra" in result[4:]
        assert "added" in result[4:]


def _write_token_file(tmp_path, server_id, data):
    """Helper: write a plaintext token file to tmp_path/oauth/{server_id}.json.

    Plaintext is read transparently by read_token_file() (auto-migrates).
    """
    oauth_dir = tmp_path / "oauth"
    oauth_dir.mkdir(parents=True, exist_ok=True)
    token_file = oauth_dir / f"{server_id}.json"
    token_file.write_text(json.dumps(data))
    return token_file


class TestIsSelfManagedOAuth:
    """The token-file shape distinguishes backend-managed (marketplace) tokens
    from self-managed (DCR / manual custom) tokens. Files written by the
    OAuthClientProvider flow contain a `client_info` block; backend-managed
    files do not. This must be correct because it gates whether we hit the
    Maskit auth backend or refresh against the upstream provider directly.
    """

    def test_returns_true_when_client_info_present(self, tmp_path):
        _write_token_file(tmp_path, "sentry", {
            "tokens": {"access_token": "abc", "refresh_token": "rt"},
            "client_info": {"client_id": "dcr-id-123", "redirect_uris": ["http://x"]},
        })
        assert _is_self_managed_oauth("sentry", str(tmp_path / "store.db")) is True

    def test_returns_false_when_only_tokens_present(self, tmp_path):
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "abc", "refresh_token": "rt"},
        })
        assert _is_self_managed_oauth("github", str(tmp_path / "store.db")) is False

    def test_returns_false_when_file_missing(self, tmp_path):
        assert _is_self_managed_oauth("nonexistent", str(tmp_path / "store.db")) is False

    def test_returns_false_for_invalid_server_id(self, tmp_path):
        # Path-traversal attempt — must not blow up, must not be treated as self-managed
        assert _is_self_managed_oauth("../../etc/passwd", str(tmp_path / "store.db")) is False


class TestLoadBackendOAuthTokenSelfManaged:
    """_load_backend_oauth_token must return None for self-managed token files
    so connect_upstream falls through to the OAuthClientProvider branch — that's
    the only branch that knows how to refresh DCR tokens.
    """

    @pytest.mark.anyio
    async def test_returns_none_when_client_info_present(self, tmp_path):
        _write_token_file(tmp_path, "sentry", {
            "tokens": {"access_token": "should-not-be-used"},
            "client_info": {"client_id": "x", "redirect_uris": ["http://x"]},
        })
        token = _load_backend_oauth_token("sentry", str(tmp_path / "store.db"))
        assert token is None

    @pytest.mark.anyio
    async def test_returns_token_when_client_info_absent(self, tmp_path):
        # Regression guard: backend-managed flow keeps working
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "backend-token"},
        })
        token = _load_backend_oauth_token("github", str(tmp_path / "store.db"))
        assert token == "backend-token"


class TestIsOAuthTokenExpired:
    """Pre-flight expiry check — drives whether __main__ refreshes before connect."""

    def test_self_managed_returns_false(self, tmp_path):
        # Even with an obviously expired token, self-managed must be skipped.
        _write_token_file(tmp_path, "sentry", {
            "tokens": {
                "access_token": "old",
                "refresh_token": "rt",
                "expires_in": 3600,
                "created_at": 1.0,  # Unix epoch — definitely expired
            },
            "client_info": {"client_id": "x", "redirect_uris": ["http://x"]},
        })
        assert is_oauth_token_expired("sentry", str(tmp_path / "store.db")) is False

    def test_legacy_backend_file_without_created_at_returns_true(self, tmp_path):
        # Token file written before created_at tracking — refresh proactively.
        _write_token_file(tmp_path, "github", {
            "tokens": {
                "access_token": "old",
                "refresh_token": "rt",
                "expires_in": 3600,
                # No created_at
            },
        })
        assert is_oauth_token_expired("github", str(tmp_path / "store.db")) is True

    def test_no_refresh_token_returns_false(self, tmp_path):
        # Without a refresh_token there is nothing useful to do — don't claim expired.
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "old"},
        })
        assert is_oauth_token_expired("github", str(tmp_path / "store.db")) is False

    def test_no_token_file_returns_false(self, tmp_path):
        assert is_oauth_token_expired("missing", str(tmp_path / "store.db")) is False

    def test_expired_by_created_at_plus_expires_in(self, tmp_path):
        import time
        _write_token_file(tmp_path, "github", {
            "tokens": {
                "access_token": "old",
                "refresh_token": "rt",
                "expires_in": 60,
                "created_at": time.time() - 3600,  # 1 hour ago, lifetime 60s
            },
        })
        assert is_oauth_token_expired("github", str(tmp_path / "store.db")) is True

    def test_fresh_token_returns_false(self, tmp_path):
        import time
        _write_token_file(tmp_path, "github", {
            "tokens": {
                "access_token": "fresh",
                "refresh_token": "rt",
                "expires_in": 3600,
                "created_at": time.time(),
            },
        })
        assert is_oauth_token_expired("github", str(tmp_path / "store.db")) is False

    def test_skew_window_treats_near_expiry_as_expired(self, tmp_path):
        import time
        # Token expires in 30s, default skew is 60s → should be treated as expired
        _write_token_file(tmp_path, "github", {
            "tokens": {
                "access_token": "old",
                "refresh_token": "rt",
                "expires_in": 90,
                "created_at": time.time() - 60,  # 60s ago, 90s lifetime → 30s left
            },
        })
        assert is_oauth_token_expired("github", str(tmp_path / "store.db")) is True


class _FakeBackendClient:
    """Minimal stand-in for BackendClient. Records calls so tests can assert
    the backend wasn't reached for self-managed targets.
    """

    def __init__(self, response=None):
        self._response = response
        self.calls = []

    async def refresh_oauth_token(self, server_id, refresh_token):
        self.calls.append((server_id, refresh_token))
        return self._response


class TestRefreshBackendOAuthToken:
    """refresh_backend_oauth_token must NOT call the backend for self-managed
    targets (Sentry-via-DCR was hitting api.maskitmcp.com — wrong endpoint).
    """

    @pytest.mark.anyio
    async def test_self_managed_skips_backend_call(self, tmp_path):
        _write_token_file(tmp_path, "sentry", {
            "tokens": {"access_token": "old", "refresh_token": "rt"},
            "client_info": {"client_id": "x", "redirect_uris": ["http://x"]},
        })
        client = _FakeBackendClient(response={"access_token": "should-not-be-used"})

        result = await refresh_backend_oauth_token(
            "sentry", str(tmp_path / "store.db"), client
        )

        assert result is None
        assert client.calls == []  # Backend must not be called

    @pytest.mark.anyio
    async def test_backend_managed_calls_backend_and_persists(self, tmp_path):
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "old", "refresh_token": "rt-old"},
        })
        client = _FakeBackendClient(response={
            "access_token": "new-token",
            "refresh_token": "rt-new",
            "expires_in": 3600,
        })

        result = await refresh_backend_oauth_token(
            "github", str(tmp_path / "store.db"), client
        )

        assert result == "new-token"
        assert client.calls == [("github", "rt-old")]

        # New tokens persisted with created_at stamp
        saved = read_token_file(tmp_path / "oauth" / "github.json")
        assert saved["tokens"]["access_token"] == "new-token"
        assert saved["tokens"]["refresh_token"] == "rt-new"
        assert "created_at" in saved["tokens"]

    @pytest.mark.anyio
    async def test_no_refresh_token_returns_none(self, tmp_path):
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "old"},  # No refresh_token
        })
        client = _FakeBackendClient(response={"access_token": "x"})

        result = await refresh_backend_oauth_token(
            "github", str(tmp_path / "store.db"), client
        )

        assert result is None
        assert client.calls == []

    @pytest.mark.anyio
    async def test_backend_returns_none_propagates(self, tmp_path):
        _write_token_file(tmp_path, "github", {
            "tokens": {"access_token": "old", "refresh_token": "rt"},
        })
        client = _FakeBackendClient(response=None)  # Backend refused refresh

        result = await refresh_backend_oauth_token(
            "github", str(tmp_path / "store.db"), client
        )

        assert result is None
        assert client.calls == [("github", "rt")]


class TestSaveBackendOAuthTokensCreatedAt:
    """Newly-saved tokens get a created_at stamp so future expiry checks have
    a baseline. Existing created_at values must be preserved.
    """

    @pytest.mark.anyio
    async def test_save_stamps_created_at_when_missing(self, tmp_path):
        import time
        before = time.time()
        _save_backend_oauth_tokens(
            "github",
            str(tmp_path / "store.db"),
            {"access_token": "x", "refresh_token": "rt"},
        )
        saved = read_token_file(tmp_path / "oauth" / "github.json")
        created_at = saved["tokens"]["created_at"]
        assert before <= created_at <= time.time() + 1

    @pytest.mark.anyio
    async def test_save_preserves_existing_created_at(self, tmp_path):
        # If the backend response itself includes created_at, don't clobber it
        _save_backend_oauth_tokens(
            "github",
            str(tmp_path / "store.db"),
            {"access_token": "x", "refresh_token": "rt", "created_at": 12345.0},
        )
        saved = read_token_file(tmp_path / "oauth" / "github.json")
        assert saved["tokens"]["created_at"] == 12345.0
