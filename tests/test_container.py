"""Tests for container.py helpers used by the container-lifecycle plan.

Pure-function helpers are tested directly. Async helpers (`stop_container`,
`sweep_server_orphans`) patch `anyio.run_process` so no real container runtime
is needed. A key invariant pinned by these tests: no code path ever invokes
`<runtime> rm` — Maskit only stops, never removes.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

import anyio
import pytest

from maskit import container as container_mod
from maskit.container import (
    MASKIT_LABEL_KEY,
    MASKIT_NAME_PREFIX,
    extract_container_name,
    inject_container_label,
    inject_container_name,
    is_container_run_command,
    stop_container,
    sweep_server_orphans,
    validate_user_container_name,
)


# ----------------------------- Pure-function tests ---------------------------


class TestIsContainerRunCommand:
    @pytest.mark.parametrize("runtime", ["docker", "podman", "nerdctl", "finch"])
    def test_runtime_run_is_container(self, runtime):
        assert is_container_run_command(runtime, ["run", "img"]) is True

    def test_runtime_path_prefix_is_stripped(self):
        assert is_container_run_command("/usr/local/bin/docker", ["run", "img"]) is True

    def test_non_run_subcommand_is_not_container(self):
        assert is_container_run_command("docker", ["ps"]) is False
        assert is_container_run_command("docker", ["exec", "x", "sh"]) is False
        assert is_container_run_command("docker", ["create", "img"]) is False

    def test_empty_args_is_not_container(self):
        assert is_container_run_command("docker", []) is False

    def test_non_container_command(self):
        assert is_container_run_command("uvx", ["run", "x"]) is False
        assert is_container_run_command("npx", ["mcp-server-foo"]) is False
        assert is_container_run_command("bash", ["run", "thing"]) is False


class TestExtractContainerName:
    def test_separate_flag(self):
        assert extract_container_name(["run", "--name", "foo", "img"]) == "foo"

    def test_equals_form(self):
        assert extract_container_name(["run", "--name=bar", "img"]) == "bar"

    def test_absent_returns_none(self):
        assert extract_container_name(["run", "img"]) is None
        assert extract_container_name([]) is None

    def test_dangling_flag_returns_none(self):
        assert extract_container_name(["run", "--name"]) is None

    def test_empty_value_returns_none(self):
        assert extract_container_name(["run", "--name="]) is None

    def test_first_occurrence_wins(self):
        assert (
            extract_container_name(["run", "--name", "first", "--name=second", "img"])
            == "first"
        )


class TestInjectContainerName:
    def test_inserts_after_run(self):
        result = inject_container_name(["run", "-i", "img"], "maskit-x")
        assert result == ["run", "--name", "maskit-x", "-i", "img"]

    def test_preserves_user_name(self):
        original = ["run", "--name", "user-pick", "img"]
        assert inject_container_name(original, "maskit-x") == original

    def test_preserves_user_equals_form(self):
        original = ["run", "--name=user-pick", "img"]
        assert inject_container_name(original, "maskit-x") == original

    def test_no_run_returns_copy_unchanged(self):
        original = ["exec", "container", "sh"]
        result = inject_container_name(original, "maskit-x")
        assert result == original
        assert result is not original  # always a copy

    def test_returns_new_list_when_injecting(self):
        original = ["run", "img"]
        result = inject_container_name(original, "maskit-x")
        assert result is not original
        assert original == ["run", "img"]  # input not mutated


class TestInjectContainerLabel:
    def test_inserts_after_run(self):
        result = inject_container_label(["run", "img"], MASKIT_LABEL_KEY, "abc")
        assert result == ["run", "--label", f"{MASKIT_LABEL_KEY}=abc", "img"]

    def test_always_inserts_even_if_user_has_label(self):
        # Multiple --label flags are valid; injection is unconditional.
        original = ["run", "--label", "user.tag=1", "img"]
        result = inject_container_label(original, MASKIT_LABEL_KEY, "abc")
        assert result == [
            "run",
            "--label",
            f"{MASKIT_LABEL_KEY}=abc",
            "--label",
            "user.tag=1",
            "img",
        ]

    def test_no_run_returns_copy_unchanged(self):
        original = ["ps", "-aq"]
        result = inject_container_label(original, MASKIT_LABEL_KEY, "abc")
        assert result == original
        assert result is not original


class TestValidateUserContainerName:
    @pytest.mark.parametrize("name", ["foo", "Foo", "f", "foo_bar", "foo.bar", "foo-bar-1"])
    def test_valid(self, name):
        assert validate_user_container_name(name) is None

    @pytest.mark.parametrize("name", ["_foo", "-foo", ".foo", "1foo"])
    def test_valid_with_leading_alnum(self, name):
        # Per docker spec, leading char must be alnum.
        # "_foo", "-foo", ".foo" are rejected; "1foo" is allowed.
        if name == "1foo":
            assert validate_user_container_name(name) is None
        else:
            assert validate_user_container_name(name) is not None

    def test_empty_rejected(self):
        assert validate_user_container_name("") is not None

    @pytest.mark.parametrize(
        "name", ["maskit-foo", f"{MASKIT_NAME_PREFIX}slack", "maskit-"]
    )
    def test_reserved_prefix_rejected(self, name):
        err = validate_user_container_name(name)
        assert err is not None
        assert "reserved" in err

    @pytest.mark.parametrize("name", ["foo bar", "foo;bar", "foo$bar", "foo/bar"])
    def test_invalid_chars_rejected(self, name):
        err = validate_user_container_name(name)
        assert err is not None
        assert "invalid" in err.lower()


# ---------------------------- Async helper tests -----------------------------


@dataclass
class _ProcCall:
    """Records one fake `anyio.run_process` invocation for assertions."""

    command: list[str]
    kwargs: dict


@dataclass
class _Recorder:
    """Test double for `anyio.run_process` — records calls, returns scripted results."""

    calls: list[_ProcCall] = field(default_factory=list)
    results: list[subprocess.CompletedProcess] = field(default_factory=list)
    raise_exc: BaseException | None = None
    hang: bool = False

    async def __call__(self, command, **kwargs):
        self.calls.append(_ProcCall(command=list(command), kwargs=kwargs))
        if self.hang:
            await anyio.sleep_forever()
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.results:
            return self.results.pop(0)
        # Default: success with empty stdout
        return subprocess.CompletedProcess(
            args=command, returncode=0, stdout=b"", stderr=b""
        )

    def all_commands(self) -> list[list[str]]:
        return [c.command for c in self.calls]

    def has_rm_call(self) -> bool:
        return any(
            len(cmd) >= 2 and cmd[1] in ("rm",) for cmd in self.all_commands()
        )


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(container_mod.anyio, "run_process", rec)
    return rec


class TestStopContainer:
    @pytest.mark.anyio
    async def test_invokes_runtime_stop_with_name(self, recorder):
        await stop_container("docker", "maskit-slack")
        assert recorder.all_commands() == [
            ["docker", "stop", "--time=3", "maskit-slack"]
        ]
        assert recorder.calls[0].kwargs.get("check") is False

    @pytest.mark.anyio
    async def test_never_calls_rm(self, recorder):
        # Critical invariant: stop only, no rm.
        await stop_container("podman", "maskit-x")
        assert recorder.has_rm_call() is False

    @pytest.mark.anyio
    async def test_nonzero_exit_logged_not_raised(self, recorder, caplog):
        recorder.results.append(
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout=b"", stderr=b"no such container: x"
            )
        )
        # Must not raise.
        await stop_container("docker", "x")
        assert any(
            "Failed to stop container x" in r.message for r in caplog.records
        )

    @pytest.mark.anyio
    async def test_timeout_swallowed(self, recorder, caplog):
        recorder.hang = True
        await stop_container("docker", "stuck", timeout=0.05)
        assert any("Timed out stopping container stuck" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_arbitrary_exception_swallowed(self, recorder, caplog):
        recorder.raise_exc = RuntimeError("boom")
        await stop_container("docker", "x")
        assert any("Error stopping container x" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_uses_provided_runtime(self, recorder):
        await stop_container("nerdctl", "foo")
        assert recorder.calls[0].command[0] == "nerdctl"


class TestSweepServerOrphans:
    @pytest.mark.anyio
    async def test_no_orphans_only_runs_ps(self, recorder):
        # ps returns empty stdout → nothing to stop.
        await sweep_server_orphans("docker", "slack-7f3a")
        cmds = recorder.all_commands()
        assert len(cmds) == 1
        assert cmds[0] == [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label={MASKIT_LABEL_KEY}=slack-7f3a",
        ]

    @pytest.mark.anyio
    async def test_stops_each_returned_id(self, recorder):
        recorder.results.append(
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"abc123\ndef456\n", stderr=b""
            )
        )
        await sweep_server_orphans("podman", "slack")
        cmds = recorder.all_commands()
        # ps + two stops
        assert cmds[0][:2] == ["podman", "ps"]
        assert cmds[1] == ["podman", "stop", "--time=3", "abc123"]
        assert cmds[2] == ["podman", "stop", "--time=3", "def456"]
        assert recorder.has_rm_call() is False

    @pytest.mark.anyio
    async def test_ps_failure_logged_no_stops(self, recorder, caplog):
        recorder.results.append(
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout=b"", stderr=b"daemon not running"
            )
        )
        await sweep_server_orphans("docker", "slack")
        # Only the ps call should have happened.
        assert len(recorder.all_commands()) == 1
        assert any(
            "Failed to list orphan containers for slack" in r.message
            for r in caplog.records
        )

    @pytest.mark.anyio
    async def test_ps_timeout_logged_no_crash(self, recorder, caplog):
        recorder.hang = True
        await sweep_server_orphans("docker", "slack", timeout=0.05)
        assert any(
            "Timed out listing orphan containers for slack" in r.message
            for r in caplog.records
        )

    @pytest.mark.anyio
    async def test_ps_exception_swallowed(self, recorder, caplog):
        recorder.raise_exc = RuntimeError("ps boom")
        await sweep_server_orphans("docker", "slack")
        assert any(
            "Error listing orphan containers for slack" in r.message
            for r in caplog.records
        )

    @pytest.mark.anyio
    async def test_label_filter_uses_correct_key(self, recorder):
        await sweep_server_orphans("docker", "my-id")
        ps_cmd = recorder.all_commands()[0]
        # The filter expression must include MASKIT_LABEL_KEY.
        assert f"label={MASKIT_LABEL_KEY}=my-id" in ps_cmd


class TestNoRmInvariant:
    """The plan forbids any `<runtime> rm` invocation. Pin it explicitly across
    every public async helper in this module."""

    @pytest.mark.anyio
    async def test_stop_then_sweep_combined_never_rms(self, recorder):
        recorder.results.append(
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"abc\n", stderr=b""
            )
        )
        await stop_container("docker", "x")
        await sweep_server_orphans("docker", "y")
        assert recorder.has_rm_call() is False
