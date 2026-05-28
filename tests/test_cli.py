"""Tests for CLI argument parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from openmaskit import __version__
from openmaskit.cli import parse_args


class TestParseArgs:
    def test_no_args_uses_defaults(self):
        """No arguments should use default config path."""
        args = parse_args([])
        assert args.config_path == Path("openmaskit.yaml")
        assert args.web_port is None
        assert args.mcp_port is None
        assert args.oauth_port is None
        assert args.store_path is None

    def test_positional_config(self):
        """Positional argument sets config path."""
        args = parse_args(["custom.yaml"])
        assert args.config_path == Path("custom.yaml")

    def test_flag_config(self):
        """--config flag sets config path."""
        args = parse_args(["--config", "other.yaml"])
        assert args.config_path == Path("other.yaml")

    def test_short_flag_config(self):
        """-c flag sets config path."""
        args = parse_args(["-c", "short.yaml"])
        assert args.config_path == Path("short.yaml")

    def test_positional_overrides_flag(self):
        """Positional takes priority over flag."""
        args = parse_args(["pos.yaml", "--config", "flag.yaml"])
        assert args.config_path == Path("pos.yaml")

    def test_port_overrides(self):
        """Port arguments are parsed correctly."""
        args = parse_args(["-w", "8080", "-m", "8081", "-o", "8082"])
        assert args.web_port == 8080
        assert args.mcp_port == 8081
        assert args.oauth_port == 8082

    def test_long_port_flags(self):
        """Long port flags work."""
        args = parse_args(
            ["--web-port", "5000", "--mcp-port", "5001", "--oauth-port", "5002"]
        )
        assert args.web_port == 5000
        assert args.mcp_port == 5001
        assert args.oauth_port == 5002

    def test_store_path_override(self):
        """Store path argument is parsed."""
        args = parse_args(["-s", "/custom/store.db"])
        assert args.store_path == "/custom/store.db"

    def test_combined_args(self):
        """Multiple arguments can be combined."""
        args = parse_args(
            [
                "my-config.yaml",
                "-w",
                "9000",
                "--mcp-port",
                "9001",
                "-o",
                "9002",
                "-s",
                "/data/openmaskit.db",
            ]
        )
        assert args.config_path == Path("my-config.yaml")
        assert args.web_port == 9000
        assert args.mcp_port == 9001
        assert args.oauth_port == 9002
        assert args.store_path == "/data/openmaskit.db"


class TestVersion:
    def test_version_returns_string(self):
        """__version__ is a non-empty string matching pyproject.toml or 'unknown'."""
        assert isinstance(__version__, str)
        assert len(__version__) > 0
        assert __version__ == "0.1.0" or __version__ == "unknown"
