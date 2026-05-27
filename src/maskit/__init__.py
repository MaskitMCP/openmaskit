"""Maskit - MCP server wrapper that masks sensitive fields."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("maskit")
except PackageNotFoundError:
    # Running from source without the package installed
    try:
        from pathlib import Path
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        _pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        with open(_pyproject, "rb") as _f:
            __version__ = tomllib.load(_f).get("project", {}).get("version", "unknown")
    except Exception:
        __version__ = "unknown"
