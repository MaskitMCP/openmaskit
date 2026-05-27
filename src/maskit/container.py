"""Container runtime detection and command preprocessing."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from functools import lru_cache

import anyio

logger = logging.getLogger(__name__)

# Supported container runtimes in order of preference
CONTAINER_RUNTIMES = ["docker", "podman", "nerdctl", "finch"]

# Label key Maskit applies to every container it starts. Used for the boot-time
# orphan sweep so we never operate on a container we didn't create.
MASKIT_LABEL_KEY = "maskit.server_id"

# Reserved prefix for Maskit-generated container names. User-supplied names
# starting with this are rejected to avoid namespace ambiguity.
MASKIT_NAME_PREFIX = "maskit-"

# Docker's own container-name spec: leading alnum, then alnum/_/./-.
_CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")


@lru_cache(maxsize=1)
def detect_container_runtime() -> str | None:
    """
    Auto-detect available container runtime.

    Checks for docker, podman, nerdctl, finch in order of preference.
    Returns the first available runtime command, or None if none found.

    Result is cached after first call.
    """
    for runtime in CONTAINER_RUNTIMES:
        if shutil.which(runtime):
            logger.info(f"Detected container runtime: {runtime}")
            return runtime

    logger.warning("No container runtime detected (checked: docker, podman, nerdctl, finch)")
    return None


def get_container_runtime(override: str | None = None) -> str | None:
    """
    Get the container runtime to use.

    Args:
        override: Optional user-specified runtime (from config)

    Returns:
        Runtime command to use, or None if none available
    """
    # Use override if provided
    if override:
        if shutil.which(override):
            logger.info(f"Using configured container runtime: {override}")
            return override
        else:
            logger.warning(f"Configured runtime '{override}' not found in PATH, falling back to auto-detect")

    # Fall back to auto-detection
    return detect_container_runtime()


def preprocess_container_command(command: str, runtime: str | None = None) -> tuple[str, bool]:
    """
    Preprocess a command to substitute container runtime.

    If the command starts with 'docker', replaces it with the detected/configured runtime.

    Args:
        command: Original command string
        runtime: Detected or configured runtime (if None, will auto-detect)

    Returns:
        Tuple of (processed_command, was_substituted)
    """
    # Split command to check first word
    parts = command.split(maxsplit=1)
    if not parts or parts[0] != "docker":
        # Not a docker command, return as-is
        return command, False

    # Get runtime
    if runtime is None:
        runtime = detect_container_runtime()

    if runtime is None:
        # No runtime available, return original
        logger.error("Command requires Docker but no container runtime is available")
        return command, False

    if runtime == "docker":
        # Already docker, no substitution needed
        return command, False

    # Substitute docker with detected runtime
    substituted = command.replace("docker", runtime, 1)
    logger.info(f"Substituted container runtime: docker → {runtime}")
    return substituted, True


def validate_container_runtime(runtime: str) -> bool:
    """
    Validate that a container runtime is available.

    Args:
        runtime: Runtime name to validate

    Returns:
        True if runtime is available in PATH
    """
    return shutil.which(runtime) is not None


def is_container_run_command(command: str, args: list[str]) -> bool:
    """True iff `command` is a known container runtime and `args[0] == "run"`.

    Gates on `run` exactly so `docker exec`, `docker ps`, etc. are not treated
    as containers we own and should manage.
    """
    if not args or args[0] != "run":
        return False
    base = command.rsplit("/", 1)[-1]
    return base in CONTAINER_RUNTIMES


def extract_container_name(args: list[str]) -> str | None:
    """Parse `--name X` or `--name=X` from args. Return None if absent or empty."""
    for i, a in enumerate(args):
        if a == "--name":
            if i + 1 < len(args) and args[i + 1]:
                return args[i + 1]
            return None
        if a.startswith("--name="):
            value = a.split("=", 1)[1]
            return value or None
    return None


def inject_container_name(args: list[str], name: str) -> list[str]:
    """Insert `--name <name>` right after `run` if not already present.

    If args already specify `--name` (any form), returns args unchanged.
    If `run` is not in args, returns args unchanged (caller should have
    checked `is_container_run_command` first).
    """
    if extract_container_name(args) is not None:
        return list(args)
    try:
        run_idx = args.index("run")
    except ValueError:
        return list(args)
    new_args = list(args)
    new_args[run_idx + 1 : run_idx + 1] = ["--name", name]
    return new_args


def inject_container_label(args: list[str], key: str, value: str) -> list[str]:
    """Insert `--label key=value` right after `run`.

    Always inserts (multiple `--label` flags are valid). If `run` is not in
    args, returns args unchanged.
    """
    try:
        run_idx = args.index("run")
    except ValueError:
        return list(args)
    new_args = list(args)
    new_args[run_idx + 1 : run_idx + 1] = ["--label", f"{key}={value}"]
    return new_args


def has_rm_flag(args: list[str]) -> bool:
    """True iff args contain `--rm` (any form: bare, `--rm=true`, `--rm=True`)."""
    for a in args:
        if a == "--rm":
            return True
        if a.startswith("--rm="):
            value = a.split("=", 1)[1].lower()
            return value in ("true", "1", "yes")
    return False


def validate_user_container_name(name: str) -> str | None:
    """Validate a user-supplied container name.

    Returns an error message if invalid, None if OK. Two checks:
    1. Matches docker's own naming spec (alnum start, alnum/_/./- after).
    2. Does not use the reserved `maskit-` prefix.
    """
    if not name:
        return "Container name cannot be empty"
    if name.startswith(MASKIT_NAME_PREFIX):
        return (
            f"Container name '{name}' uses the reserved '{MASKIT_NAME_PREFIX}' "
            "prefix; choose a different name"
        )
    if not _CONTAINER_NAME_RE.match(name):
        return (
            f"Container name '{name}' is invalid: must start with a letter or "
            "digit and contain only letters, digits, '_', '.', or '-'"
        )
    return None


async def stop_container(runtime: str, name: str, timeout: float = 5.0) -> None:
    """Best-effort `<runtime> stop --time=3 <name>`. Errors logged, never raised.

    No `rm` is issued; cleanup of stopped containers is the caller's contract
    (typically via `--rm` on the original `run`).
    """
    try:
        with anyio.fail_after(timeout):
            result = await anyio.run_process(
                [runtime, "stop", "--time=3", name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            logger.warning(
                "Failed to stop container %s via %s: %s", name, runtime, stderr
            )
        else:
            logger.info("Stopped container %s via %s", name, runtime)
    except TimeoutError:
        logger.warning("Timed out stopping container %s via %s", name, runtime)
    except Exception as exc:
        logger.warning("Error stopping container %s via %s: %s", name, runtime, exc)


async def sweep_server_orphans(
    runtime: str, server_id: str, timeout: float = 10.0
) -> None:
    """Stop every container labeled `maskit.server_id=<server_id>`.

    Used at boot and before a target restart to clear crash-orphans without
    touching containers Maskit didn't start. Best-effort: errors are logged,
    never raised, and a failure on one container does not block the others.
    """
    label_filter = f"label={MASKIT_LABEL_KEY}={server_id}"
    try:
        with anyio.fail_after(timeout):
            result = await anyio.run_process(
                [runtime, "ps", "-aq", "--filter", label_filter],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
    except TimeoutError:
        logger.warning(
            "Timed out listing orphan containers for %s via %s", server_id, runtime
        )
        return
    except Exception as exc:
        logger.warning(
            "Error listing orphan containers for %s via %s: %s",
            server_id,
            runtime,
            exc,
        )
        return

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        logger.warning(
            "Failed to list orphan containers for %s: %s", server_id, stderr
        )
        return

    ids = result.stdout.decode("utf-8", errors="replace").split()
    if not ids:
        return

    logger.info("Stopping %d orphan container(s) for %s", len(ids), server_id)
    for cid in ids:
        await stop_container(runtime, cid)
