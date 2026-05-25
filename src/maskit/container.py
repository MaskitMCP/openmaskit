"""Container runtime detection and command preprocessing."""

from __future__ import annotations

import logging
import shutil
from functools import lru_cache

logger = logging.getLogger(__name__)

# Supported container runtimes in order of preference
CONTAINER_RUNTIMES = ["docker", "podman", "nerdctl", "finch"]


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
