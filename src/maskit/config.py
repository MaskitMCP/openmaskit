from __future__ import annotations

from pathlib import Path

import yaml

from maskit.models import (
    MaskingRuleConfig,
    MultiTargetConfig,
    TargetConfig,
    UpstreamHttpConfig,
    UpstreamStdioConfig,
)


def _parse_upstream(raw: dict) -> UpstreamStdioConfig | UpstreamHttpConfig:
    transport = raw.get("transport", "stdio")
    if transport == "stdio":
        return UpstreamStdioConfig(**raw)
    elif transport in ("http", "sse"):
        return UpstreamHttpConfig(**raw)
    else:
        raise ValueError(f"Unknown transport: {transport}")


def load_config(path: Path | None = None) -> MultiTargetConfig:
    if path is None:
        path = Path("maskit.yaml")
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if "targets" in raw:
        targets = {}
        for name, target_raw in raw["targets"].items():
            upstream = _parse_upstream(target_raw.get("upstream", {}))
            rules = [MaskingRuleConfig(**r) for r in target_raw.get("rules", [])]
            targets[name] = TargetConfig(upstream=upstream, rules=rules)
        return MultiTargetConfig(
            targets=targets,
            web_port=raw.get("web_port", 9473),
            mcp_port=raw.get("mcp_port", 9474),
            store_path=raw.get("store_path", "~/.maskit/store.db"),
        )

    # Legacy single-upstream format — wrap as target "default"
    upstream = _parse_upstream(raw.get("upstream", {}))
    rules = [MaskingRuleConfig(**r) for r in raw.get("rules", [])]
    target = TargetConfig(upstream=upstream, rules=rules)
    return MultiTargetConfig(
        targets={"default": target},
        web_port=raw.get("web_port", 9473),
        mcp_port=raw.get("mcp_port", 9474),
        store_path=raw.get("store_path", "~/.maskit/store.db"),
    )
