"""Integration tests for container lifecycle wiring in `connect_upstream`.

Pin the contract that for stdio upstreams whose command is a container `run`:
  * pre-start sweep of orphan containers runs first
  * `--name` is injected (or user's is preserved) before stdio_client starts
  * `--label openmaskit.server_id=<id>` is always injected
  * `stop_container` runs on context exit — normal exit AND exception path
  * no rm is ever called (verified via `stop_container` being a recorded mock)
  * missing `--rm` logs a WARNING but does not block

Non-container commands (uvx, npx, etc.) and callers without a server_id are
left untouched.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import pytest

from openmaskit import container as container_mod
from openmaskit.container import OPENMASKIT_LABEL_KEY, OPENMASKIT_NAME_PREFIX
from openmaskit.models import UpstreamStdioConfig
from openmaskit.proxy import upstream as upstream_mod
from openmaskit.proxy.upstream import connect_upstream


# --------------------------------- Test doubles ------------------------------


@dataclass
class _StdioCall:
    params: Any


@dataclass
class _FakeStdioClient:
    """Drop-in for `mcp.client.stdio.stdio_client`.

    Captures the `StdioServerParameters` passed in and yields placeholder
    streams. Optionally raises during the yield to simulate an upstream
    failure mid-session.
    """

    calls: list[_StdioCall] = field(default_factory=list)
    raise_during_yield: BaseException | None = None

    def __call__(self, params, errlog=None):
        self.calls.append(_StdioCall(params=params))
        return self._ctx()

    @asynccontextmanager
    async def _ctx(self):
        try:
            yield (None, None)
            if self.raise_during_yield is not None:
                raise self.raise_during_yield
        finally:
            pass


@dataclass
class _Recorder:
    """Records calls to stop_container / sweep_server_orphans."""

    stop_calls: list[tuple[str, str]] = field(default_factory=list)
    sweep_calls: list[tuple[str, str]] = field(default_factory=list)

    async def stop(self, runtime: str, name: str, timeout: float = 5.0) -> None:
        self.stop_calls.append((runtime, name))

    async def sweep(self, runtime: str, server_id: str, timeout: float = 10.0) -> None:
        self.sweep_calls.append((runtime, server_id))


@pytest.fixture
def fakes(monkeypatch):
    fake_stdio = _FakeStdioClient()
    rec = _Recorder()

    # Patch the symbols actually used by connect_upstream.
    monkeypatch.setattr(upstream_mod, "stdio_client", fake_stdio)
    monkeypatch.setattr(upstream_mod, "stop_container", rec.stop)
    monkeypatch.setattr(upstream_mod, "sweep_server_orphans", rec.sweep)
    # Force a deterministic runtime so tests don't depend on the host's PATH.
    monkeypatch.setattr(upstream_mod, "get_container_runtime", lambda _: "docker")

    return fake_stdio, rec


# ----------------------------- Container path tests --------------------------


class TestContainerInjection:
    @pytest.mark.anyio
    async def test_injects_default_name_and_label(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(
            command="docker", args=["run", "--rm", "-i", "ghcr.io/foo/mcp"]
        )

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="slack-7f3a"
        ):
            pass

        assert len(fake_stdio.calls) == 1
        params = fake_stdio.calls[0].params
        assert params.args == [
            "run",
            "--label",
            f"{OPENMASKIT_LABEL_KEY}=slack-7f3a",
            "--name",
            f"{OPENMASKIT_NAME_PREFIX}slack-7f3a",
            "--rm",
            "-i",
            "ghcr.io/foo/mcp",
        ]

    @pytest.mark.anyio
    async def test_user_name_is_preserved(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(
            command="docker",
            args=["run", "--rm", "--name", "user-pick", "ghcr.io/foo/mcp"],
        )

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="slack"
        ):
            pass

        params = fake_stdio.calls[0].params
        # Default name was NOT added; user's --name remains.
        assert "--name" in params.args
        name_idx = params.args.index("--name")
        assert params.args[name_idx + 1] == "user-pick"
        # Stop targets the user's name, not the default.
        assert rec.stop_calls == [("docker", "user-pick")]

    @pytest.mark.anyio
    async def test_label_always_injected_even_when_user_has_other_labels(
        self, fakes, tmp_path
    ):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(
            command="docker",
            args=["run", "--rm", "--label", "user.tag=1", "img"],
        )

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ):
            pass

        params = fake_stdio.calls[0].params
        assert f"{OPENMASKIT_LABEL_KEY}=svc" in params.args

    @pytest.mark.anyio
    async def test_sweep_runs_before_stdio_client(self, fakes, tmp_path):
        """Pre-start sweep must execute before stdio_client is invoked."""
        fake_stdio, rec = fakes

        # Capture ordering by wrapping the recorder methods.
        order: list[str] = []

        original_sweep = rec.sweep
        original_call = fake_stdio.__call__

        async def ordered_sweep(*args, **kwargs):
            order.append("sweep")
            await original_sweep(*args, **kwargs)

        def ordered_stdio(*args, **kwargs):
            order.append("stdio")
            return original_call(*args, **kwargs)

        # Patch the names that connect_upstream looks up.
        from unittest.mock import patch

        with patch.object(upstream_mod, "sweep_server_orphans", ordered_sweep), \
             patch.object(upstream_mod, "stdio_client", ordered_stdio):
            cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])
            async with connect_upstream(
                cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
            ):
                pass

        assert order == ["sweep", "stdio"]
        assert rec.sweep_calls == [("docker", "svc")]


class TestContainerCleanup:
    @pytest.mark.anyio
    async def test_stop_called_on_normal_exit(self, fakes, tmp_path):
        _, rec = fakes
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ):
            pass

        assert rec.stop_calls == [("docker", f"{OPENMASKIT_NAME_PREFIX}svc")]

    @pytest.mark.anyio
    async def test_stop_called_on_exception_during_yield(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        fake_stdio.raise_during_yield = RuntimeError("upstream died")
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])

        with pytest.raises(RuntimeError, match="upstream died"):
            async with connect_upstream(
                cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
            ):
                pass

        # Cleanup must still have fired despite the exception.
        assert rec.stop_calls == [("docker", f"{OPENMASKIT_NAME_PREFIX}svc")]

    @pytest.mark.anyio
    async def test_stop_called_when_caller_raises(self, fakes, tmp_path):
        _, rec = fakes
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])

        with pytest.raises(ValueError, match="caller fail"):
            async with connect_upstream(
                cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
            ):
                raise ValueError("caller fail")

        assert rec.stop_calls == [("docker", f"{OPENMASKIT_NAME_PREFIX}svc")]


class TestMissingRmWarning:
    @pytest.mark.anyio
    async def test_warns_when_rm_absent(self, fakes, tmp_path, caplog):
        cfg = UpstreamStdioConfig(command="docker", args=["run", "-i", "img"])

        with caplog.at_level("WARNING"):
            async with connect_upstream(
                cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
            ):
                pass

        msgs = [r.message for r in caplog.records]
        assert any("missing --rm" in m and "svc" in m for m in msgs), msgs

    @pytest.mark.anyio
    async def test_no_warning_when_rm_present(self, fakes, tmp_path, caplog):
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])

        with caplog.at_level("WARNING"):
            async with connect_upstream(
                cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
            ):
                pass

        assert not any("missing --rm" in r.message for r in caplog.records)


# ------------------------- Non-container / passthrough -----------------------


class TestNonContainerPath:
    @pytest.mark.anyio
    async def test_uvx_command_untouched(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(command="uvx", args=["mcp-server-time"])

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="time"
        ):
            pass

        params = fake_stdio.calls[0].params
        assert params.args == ["mcp-server-time"]  # untouched
        assert rec.stop_calls == []  # never called
        assert rec.sweep_calls == []

    @pytest.mark.anyio
    async def test_docker_non_run_subcommand_untouched(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(command="docker", args=["exec", "container", "sh"])

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ):
            pass

        params = fake_stdio.calls[0].params
        assert params.args == ["exec", "container", "sh"]
        assert rec.stop_calls == []
        assert rec.sweep_calls == []

    @pytest.mark.anyio
    async def test_no_server_id_skips_container_mgmt(self, fakes, tmp_path):
        fake_stdio, rec = fakes
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])

        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id=None
        ):
            pass

        # Without a server_id we can't form a deterministic name/label, so
        # the whole feature is opt-out.
        params = fake_stdio.calls[0].params
        assert params.args == ["run", "--rm", "img"]
        assert rec.stop_calls == []
        assert rec.sweep_calls == []

    @pytest.mark.anyio
    async def test_no_runtime_skips_container_mgmt(self, monkeypatch, tmp_path):
        """When no container runtime is available, container mgmt is skipped
        (the underlying stdio_client invocation will fail naturally)."""
        fake_stdio = _FakeStdioClient()
        rec = _Recorder()
        monkeypatch.setattr(upstream_mod, "stdio_client", fake_stdio)
        monkeypatch.setattr(upstream_mod, "stop_container", rec.stop)
        monkeypatch.setattr(upstream_mod, "sweep_server_orphans", rec.sweep)
        monkeypatch.setattr(upstream_mod, "get_container_runtime", lambda _: None)

        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ):
            pass

        assert rec.stop_calls == []
        assert rec.sweep_calls == []


# ------------------------- Runtime substitution coupling ---------------------


class TestRuntimeSubstitution:
    @pytest.mark.anyio
    async def test_stop_uses_substituted_runtime(self, monkeypatch, tmp_path):
        fake_stdio = _FakeStdioClient()
        rec = _Recorder()
        monkeypatch.setattr(upstream_mod, "stdio_client", fake_stdio)
        monkeypatch.setattr(upstream_mod, "stop_container", rec.stop)
        monkeypatch.setattr(upstream_mod, "sweep_server_orphans", rec.sweep)
        # Force runtime to be podman (e.g., on a podman-only host).
        monkeypatch.setattr(upstream_mod, "get_container_runtime", lambda _: "podman")

        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ):
            pass

        # Stop call targets podman, not the original docker.
        assert rec.stop_calls == [("podman", f"{OPENMASKIT_NAME_PREFIX}svc")]
        assert rec.sweep_calls == [("podman", "svc")]


# ------------------------- Module wiring sanity check ------------------------


def test_container_module_imports_match():
    """Defense in depth: connect_upstream uses the *imported* symbols, so
    monkeypatching `upstream_mod.stop_container` must really reroute calls.
    """
    assert upstream_mod.stop_container is container_mod.stop_container
    assert upstream_mod.sweep_server_orphans is container_mod.sweep_server_orphans


# ---------------- Yielded container_info contract (for stash on TargetState) -


class TestYieldedContainerInfo:
    @pytest.mark.anyio
    async def test_container_yield_is_runtime_and_name(self, fakes, tmp_path):
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ) as yielded:
            assert isinstance(yielded, tuple) and len(yielded) == 3
            _, _, container_info = yielded
            assert container_info == ("docker", f"{OPENMASKIT_NAME_PREFIX}svc")

    @pytest.mark.anyio
    async def test_container_yield_uses_user_name(self, fakes, tmp_path):
        cfg = UpstreamStdioConfig(
            command="docker",
            args=["run", "--rm", "--name", "user-pick", "img"],
        )
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="svc"
        ) as (_, _, container_info):
            assert container_info == ("docker", "user-pick")

    @pytest.mark.anyio
    async def test_non_container_yields_none(self, fakes, tmp_path):
        cfg = UpstreamStdioConfig(command="uvx", args=["mcp-server-time"])
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id="time"
        ) as (_, _, container_info):
            assert container_info is None

    @pytest.mark.anyio
    async def test_no_server_id_yields_none(self, fakes, tmp_path):
        cfg = UpstreamStdioConfig(command="docker", args=["run", "--rm", "img"])
        async with connect_upstream(
            cfg, store_path=str(tmp_path / "store.db"), server_id=None
        ) as (_, _, container_info):
            assert container_info is None
