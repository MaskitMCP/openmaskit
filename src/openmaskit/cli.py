"""Command-line argument parsing for OpenMaskit."""

from __future__ import annotations

import argparse
from pathlib import Path

from openmaskit import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    description = """OpenMaskit - MCP server proxy that masks sensitive data

Drop-in proxy between AI coding agents and MCP servers. OpenMaskit intercepts
tool responses to mask/strip sensitive fields (API keys, emails, hostnames),
blocks dangerous operations with guardrails, and provides a web dashboard
for configuration and monitoring."""

    epilog = """Environment Variables:
  OPENMASKIT_HOST         Bind address (default: 127.0.0.1)

Examples:
  openmaskit                           Uses ./openmaskit.yaml with defaults
  openmaskit slack-config.yaml         Custom config file
  openmaskit --web-port 8080           Override web port
  openmaskit -w 8080 -m 8081 -o 8082   Override all ports
  OPENMASKIT_HOST=0.0.0.0 openmaskit       Bind to all interfaces

Documentation: https://github.com/MaskitMCP/openmaskit"""

    parser = argparse.ArgumentParser(
        prog="openmaskit",
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
        help="Path to YAML configuration file (default: openmaskit.yaml)",
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

    # Store path
    parser.add_argument(
        "-s", "--store-path",
        type=str,
        help="SQLite database path (default: ~/.openmaskit/store.db)",
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"openmaskit {__version__}",
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
        args.config_path = Path("openmaskit.yaml")

    return args
