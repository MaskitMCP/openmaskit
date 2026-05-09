from __future__ import annotations

from pydantic import BaseModel, Field


class HttpOAuthConfig(BaseModel):
    client_id: str
    callback_port: int = 3118


class UpstreamStdioConfig(BaseModel):
    transport: str = "stdio"
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class UpstreamHttpConfig(BaseModel):
    transport: str = "http"
    url: str
    oauth: HttpOAuthConfig | None = None


class MaskingRuleConfig(BaseModel):
    tool_name: str
    field_path: str
    alias_prefix: str | None = None


class Config(BaseModel):
    upstream: UpstreamStdioConfig | UpstreamHttpConfig
    web_port: int = 9473
    mcp_port: int = 9474
    store_path: str = "~/.maskit/store.db"
    rules: list[MaskingRuleConfig] = Field(default_factory=list)
