from __future__ import annotations

from pathlib import Path

import yaml

from openmaskit.models import (
    GuardrailConfig,
    InjectionConfig,
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


def load_config(
    path: Path | None = None,
    web_port: int | None = None,
    mcp_port: int | None = None,
    store_path: str | None = None,
) -> MultiTargetConfig:
    if path is None:
        path = Path("openmaskit.yaml")
    if not path.exists():
        config = MultiTargetConfig(
            targets={},
            web_port=9473,
            mcp_port=9474,
            store_path="~/.openmaskit/store.db",
        )
        if web_port is not None:
            config.web_port = web_port
        if mcp_port is not None:
            config.mcp_port = mcp_port
        if store_path is not None:
            config.store_path = store_path
        return config

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    if "targets" in raw:
        targets = {}
        for name, target_raw in raw["targets"].items():
            upstream = _parse_upstream(target_raw.get("upstream", {}))
            rules = [MaskingRuleConfig(**r) for r in target_raw.get("rules", [])]
            guardrails = [GuardrailConfig(**g) for g in target_raw.get("guardrails", [])]
            injections = [InjectionConfig(**i) for i in target_raw.get("injections", [])]
            targets[name] = TargetConfig(upstream=upstream, rules=rules, guardrails=guardrails, injections=injections)
        config = MultiTargetConfig(
            targets=targets,
            web_port=raw.get("web_port", 9473),
            mcp_port=raw.get("mcp_port", 9474),
            store_path=raw.get("store_path", "~/.openmaskit/store.db"),
        )
        if web_port is not None:
            config.web_port = web_port
        if mcp_port is not None:
            config.mcp_port = mcp_port
        if store_path is not None:
            config.store_path = store_path
        return config

    # Legacy single-upstream format — wrap as target "default"
    if "upstream" not in raw:
        config = MultiTargetConfig(
            targets={},
            web_port=raw.get("web_port", 9473),
            mcp_port=raw.get("mcp_port", 9474),
            store_path=raw.get("store_path", "~/.openmaskit/store.db"),
        )
        if web_port is not None:
            config.web_port = web_port
        if mcp_port is not None:
            config.mcp_port = mcp_port
        if store_path is not None:
            config.store_path = store_path
        return config

    upstream = _parse_upstream(raw["upstream"])
    rules = [MaskingRuleConfig(**r) for r in raw.get("rules", [])]
    guardrails = [GuardrailConfig(**g) for g in raw.get("guardrails", [])]
    injections = [InjectionConfig(**i) for i in raw.get("injections", [])]
    target = TargetConfig(upstream=upstream, rules=rules, guardrails=guardrails, injections=injections)
    config = MultiTargetConfig(
        targets={"default": target},
        web_port=raw.get("web_port", 9473),
        mcp_port=raw.get("mcp_port", 9474),
        store_path=raw.get("store_path", "~/.openmaskit/store.db"),
    )
    if web_port is not None:
        config.web_port = web_port
    if mcp_port is not None:
        config.mcp_port = mcp_port
    if store_path is not None:
        config.store_path = store_path
    return config
