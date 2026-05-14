"""Command-line argument parsing for Maskit."""

from __future__ import annotations

import argparse
from pathlib import Path


def get_version() -> str:
    """Get version from package metadata."""
    # Try importlib.metadata first (works for installed packages)
    try:
        from importlib.metadata import version
        return version("maskit")
    except Exception:
        pass

    # Fallback: read from pyproject.toml (development mode)
    try:
        # Python 3.11+ has tomllib built-in
        try:
            import tomllib
        except ImportError:
            # Python 3.10 fallback
            import tomli as tomllib  # type: ignore

        pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject.exists():
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
                return data.get("project", {}).get("version", "unknown")
    except Exception:
        pass

    return "unknown"


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    description = """Maskit - MCP server proxy that masks sensitive data

Drop-in proxy between AI coding agents and MCP servers. Maskit intercepts
tool responses to mask/strip sensitive fields (API keys, emails, hostnames),
blocks dangerous operations with guardrails, and provides a web dashboard
for configuration and monitoring."""

    epilog = """Environment Variables:
  MASKIT_HOST         Bind address (default: 127.0.0.1)

Examples:
  maskit                           Uses ./maskit.yaml with defaults
  maskit slack-config.yaml         Custom config file
  maskit --web-port 8080           Override web port
  maskit -w 8080 -m 8081 -o 8082   Override all ports
  MASKIT_HOST=0.0.0.0 maskit       Bind to all interfaces

Documentation: https://github.com/AminMal/maskit"""

    parser = argparse.ArgumentParser(
        prog="maskit",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional config file argument (optional, for backward compatibility)
    parser.add_argument(
        "config_file",
        nargs="?",
        type=Path,
        default=None,
        help="Path to YAML configuration file (default: maskit.yaml)",
    )

    # Alternative --config flag
    parser.add_argument(
        "-c", "--config",
        type=Path,
        dest="config_flag",
        help="Path to YAML config (alternative to positional arg)",
    )

    # Port options
    parser.add_argument(
        "-w", "--web-port",
        type=int,
        help="Dashboard HTTP port (default: 9473)",
    )

    parser.add_argument(
        "-m", "--mcp-port",
        type=int,
        help="MCP server endpoint port (default: 9474)",
    )

    parser.add_argument(
        "-o", "--oauth-port",
        type=int,
        help="OAuth callback server port (default: 3131)",
    )

    # Store path
    parser.add_argument(
        "-s", "--store-path",
        type=str,
        help="SQLite database path (default: ~/.maskit/store.db)",
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"maskit {get_version()}",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Argument list (defaults to sys.argv[1:])

    Returns:
        Parsed arguments with resolved config_path
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # Resolve config file priority: positional > flag > default
    if args.config_file:
        args.config_path = args.config_file
    elif args.config_flag:
        args.config_path = args.config_flag
    else:
        args.config_path = Path("maskit.yaml")

    return args
