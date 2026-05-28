"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from openmaskit.config import load_config
from openmaskit.models import MultiTargetConfig


class TestLoadConfig:
    def test_load_empty_config_uses_defaults(self, tmp_path):
        """No config file should use default values."""
        config = load_config(path=tmp_path / "nonexistent.yaml")
        assert config.web_port == 9473
        assert config.mcp_port == 9474
        assert config.oauth_port == 3131
        assert config.store_path == "~/.openmaskit/store.db"
        assert config.targets == {}

    def test_load_multi_target_config(self, tmp_path):
        """Load config with multiple targets."""
        config_yaml = dedent("""
            targets:
              time:
                upstream:
                  transport: stdio
                  command: uvx
                  args: ["mcp-server-time"]
                rules:
                  - tool_name: "get_time"
                    field_path: "timezone"
              slack:
                upstream:
                  transport: http
                  url: "https://mcp.slack.com/mcp"
                rules: []
            web_port: 8473
            mcp_port: 8474
            oauth_port: 8131
            store_path: "/custom/store.db"
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert config.web_port == 8473
        assert config.mcp_port == 8474
        assert config.oauth_port == 8131
        assert config.store_path == "/custom/store.db"
        assert len(config.targets) == 2
        assert "time" in config.targets
        assert "slack" in config.targets
        assert config.targets["time"].upstream.transport == "stdio"
        assert config.targets["time"].upstream.command == "uvx"
        assert config.targets["time"].upstream.args == ["mcp-server-time"]
        assert len(config.targets["time"].rules) == 1
        assert config.targets["slack"].upstream.transport == "http"
        assert config.targets["slack"].upstream.url == "https://mcp.slack.com/mcp"

    def test_load_legacy_single_upstream_config(self, tmp_path):
        """Backward compatibility for old config format."""
        config_yaml = dedent("""
            upstream:
              transport: stdio
              command: uvx
              args: ["mcp-server-time"]
            rules:
              - tool_name: "get_time"
                field_path: "timezone"
            web_port: 9473
            mcp_port: 9474
            store_path: "~/.openmaskit/store.db"
        """)
        config_file = tmp_path / "legacy.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert config.web_port == 9473
        assert len(config.targets) == 1
        assert "default" in config.targets
        assert config.targets["default"].upstream.transport == "stdio"
        assert len(config.targets["default"].rules) == 1

    def test_cli_overrides_yaml_ports(self, tmp_path):
        """CLI flags should override config file values."""
        config_yaml = dedent("""
            targets:
              test:
                upstream:
                  transport: stdio
                  command: echo
                rules: []
            web_port: 5000
            mcp_port: 5001
            oauth_port: 5002
            store_path: "/original/store.db"
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(
            path=config_file,
            web_port=6000,
            mcp_port=6001,
            oauth_port=6002,
            store_path="/override/store.db",
        )
        assert config.web_port == 6000
        assert config.mcp_port == 6001
        assert config.oauth_port == 6002
        assert config.store_path == "/override/store.db"

    def test_cli_overrides_empty_config(self):
        """CLI overrides should apply to empty config."""
        config = load_config(
            path=Path("nonexistent.yaml"),
            web_port=7000,
            mcp_port=7001,
            oauth_port=7002,
            store_path="/custom/store.db",
        )
        assert config.web_port == 7000
        assert config.mcp_port == 7001
        assert config.oauth_port == 7002
        assert config.store_path == "/custom/store.db"

    def test_invalid_transport_raises_error(self, tmp_path):
        """Unknown transport type should fail early."""
        config_yaml = dedent("""
            upstream:
              transport: websocket
              url: "ws://example.com"
        """)
        config_file = tmp_path / "bad.yaml"
        config_file.write_text(config_yaml)

        with pytest.raises(ValueError, match="Unknown transport"):
            load_config(path=config_file)

    def test_load_config_with_guardrails(self, tmp_path):
        """Load config with guardrails."""
        config_yaml = dedent("""
            targets:
              db:
                upstream:
                  transport: stdio
                  command: echo
                guardrails:
                  - tool_name: "run_sql"
                    pattern: "DROP TABLE"
                    message: "Destructive SQL blocked"
                rules: []
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert len(config.targets["db"].guardrails) == 1
        assert config.targets["db"].guardrails[0].pattern == "DROP TABLE"

    def test_load_config_with_injections(self, tmp_path):
        """Load config with injections."""
        config_yaml = dedent("""
            targets:
              api:
                upstream:
                  transport: http
                  url: "http://example.com"
                injections:
                  - tool_name: "run_query"
                    argument_name: "read_only"
                    value: "true"
                    mode: "set"
                rules: []
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert len(config.targets["api"].injections) == 1
        assert config.targets["api"].injections[0].argument_name == "read_only"
        assert config.targets["api"].injections[0].value == "true"

    def test_load_config_with_http_oauth(self, tmp_path):
        """Load HTTP upstream with OAuth config."""
        config_yaml = dedent("""
            targets:
              slack:
                upstream:
                  transport: http
                  url: "https://mcp.slack.com/mcp"
                  oauth:
                    client_id: "test-client-id"
                    client_secret: "test-secret"
                    scope: "channels:read"
                rules: []
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert config.targets["slack"].upstream.oauth is not None
        assert config.targets["slack"].upstream.oauth.client_id == "test-client-id"
        assert config.targets["slack"].upstream.oauth.scope == "channels:read"

    def test_load_config_with_env_vars(self, tmp_path):
        """Load stdio upstream with environment variables."""
        config_yaml = dedent("""
            targets:
              custom:
                upstream:
                  transport: stdio
                  command: node
                  args: ["server.js"]
                  env:
                    NODE_ENV: "production"
                    API_KEY: "secret"
                rules: []
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file)
        assert config.targets["custom"].upstream.env == {"NODE_ENV": "production", "API_KEY": "secret"}

    def test_partial_cli_overrides(self, tmp_path):
        """Only some CLI args should override, others use config."""
        config_yaml = dedent("""
            targets: {}
            web_port: 5000
            mcp_port: 5001
            oauth_port: 5002
            store_path: "/original/store.db"
        """)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_yaml)

        config = load_config(path=config_file, web_port=6000)
        assert config.web_port == 6000  # Overridden
        assert config.mcp_port == 5001  # From config
        assert config.oauth_port == 5002  # From config

    def test_empty_yaml_file_uses_defaults(self, tmp_path):
        """Empty YAML file should use defaults."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        config = load_config(path=config_file)
        assert config.web_port == 9473
        assert config.targets == {}
