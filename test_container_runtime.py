#!/usr/bin/env python3
"""Test container runtime detection and command preprocessing."""

from maskit.container import (
    detect_container_runtime,
    get_container_runtime,
    preprocess_container_command,
    validate_container_runtime,
)


def test_detection():
    print("=== Testing Container Runtime Detection ===")
    runtime = detect_container_runtime()
    print(f"Detected runtime: {runtime}")

    if runtime:
        print(f"✓ Runtime available: {runtime}")
    else:
        print("✗ No runtime detected")
    print()


def test_preprocessing():
    print("=== Testing Command Preprocessing ===")

    test_cases = [
        ("docker run hello-world", None),
        ("docker-compose up", None),
        ("python script.py", None),
        ("docker ps -a", "podman"),
        ("npm start", None),
    ]

    for cmd, override in test_cases:
        processed, was_sub = preprocess_container_command(cmd, override)
        if was_sub:
            print(f"✓ {cmd!r} → {processed!r}")
        else:
            print(f"  {cmd!r} (no change)")
    print()


def test_validation():
    print("=== Testing Runtime Validation ===")

    runtimes_to_test = ["docker", "podman", "nerdctl", "finch", "fake-runtime"]

    for runtime in runtimes_to_test:
        is_valid = validate_container_runtime(runtime)
        status = "✓" if is_valid else "✗"
        print(f"{status} {runtime}: {'available' if is_valid else 'not found'}")
    print()


def test_override():
    print("=== Testing Override Behavior ===")

    # Test with valid override
    runtime = get_container_runtime("podman")
    print(f"Override 'podman': {runtime}")

    # Test with invalid override (should fall back to detection)
    runtime = get_container_runtime("fake-runtime")
    print(f"Override 'fake-runtime' (fallback): {runtime}")

    # Test with no override
    runtime = get_container_runtime(None)
    print(f"No override (auto-detect): {runtime}")
    print()


if __name__ == "__main__":
    test_detection()
    test_preprocessing()
    test_validation()
    test_override()

    print("=== Summary ===")
    runtime = detect_container_runtime()
    if runtime:
        print(f"✓ Maskit will use {runtime} for containerized MCP servers")
    else:
        print("⚠ No container runtime available. Install docker, podman, nerdctl, or finch.")
