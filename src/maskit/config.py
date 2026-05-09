from __future__ import annotations

from pathlib import Path

import yaml

from maskit.models import Config, UpstreamHttpConfig, UpstreamStdioConfig


def load_config(path: Path | None = None) -> Config:
    if path is None:
        path = Path("maskit.yaml")
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    upstream_raw = raw.get("upstream", {})
    transport = upstream_raw.get("transport", "stdio")

    if transport == "stdio":
        upstream = UpstreamStdioConfig(**upstream_raw)
    elif transport in ("http", "sse"):
        upstream = UpstreamHttpConfig(**upstream_raw)
    else:
        raise ValueError(f"Unknown transport: {transport}")

    raw["upstream"] = upstream
    return Config(**raw)
