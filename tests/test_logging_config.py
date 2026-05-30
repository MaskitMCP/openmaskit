"""Tests for OPENMASKIT_LOG_LEVEL resolution and root-logger wiring."""

from __future__ import annotations

import logging

import pytest

from openmaskit.logging_config import resolve_log_level, setup_logging


class TestResolveLogLevel:
    def test_default_is_info_when_none(self) -> None:
        assert resolve_log_level(None) == logging.INFO

    def test_default_is_info_when_empty(self) -> None:
        assert resolve_log_level("") == logging.INFO

    def test_case_insensitive(self) -> None:
        assert resolve_log_level("debug") == logging.DEBUG
        assert resolve_log_level("Debug") == logging.DEBUG
        assert resolve_log_level("DEBUG") == logging.DEBUG

    def test_strips_whitespace(self) -> None:
        assert resolve_log_level("  WARNING  ") == logging.WARNING

    def test_all_supported_levels(self) -> None:
        assert resolve_log_level("DEBUG") == logging.DEBUG
        assert resolve_log_level("INFO") == logging.INFO
        assert resolve_log_level("WARNING") == logging.WARNING
        assert resolve_log_level("ERROR") == logging.ERROR

    def test_unknown_falls_back_to_info(self) -> None:
        """A typo must never silence logging or open the firehose."""
        assert resolve_log_level("verbose") == logging.INFO
        assert resolve_log_level("TRACE") == logging.INFO
        assert resolve_log_level("notalevel") == logging.INFO


class TestSetupLogging:
    @pytest.fixture(autouse=True)
    def _restore_root_logger(self):
        """Snapshot root handlers/level before each test and restore after."""
        root = logging.getLogger()
        prev_handlers = root.handlers[:]
        prev_level = root.level
        yield
        root.handlers[:] = prev_handlers
        root.setLevel(prev_level)

    def test_default_level_is_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENMASKIT_LOG_LEVEL", raising=False)
        setup_logging()
        assert logging.getLogger().level == logging.INFO

    def test_env_var_sets_debug(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENMASKIT_LOG_LEVEL", "DEBUG")
        setup_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_env_var_lowercase(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENMASKIT_LOG_LEVEL", "warning")
        setup_logging()
        assert logging.getLogger().level == logging.WARNING

    def test_env_var_invalid_falls_back_to_info(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENMASKIT_LOG_LEVEL", "loud")
        setup_logging()
        assert logging.getLogger().level == logging.INFO

    def test_replaces_existing_handlers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Repeat setup_logging() calls must not stack handlers."""
        monkeypatch.delenv("OPENMASKIT_LOG_LEVEL", raising=False)
        setup_logging()
        first = len(logging.getLogger().handlers)
        setup_logging()
        second = len(logging.getLogger().handlers)
        assert first == second == 1
