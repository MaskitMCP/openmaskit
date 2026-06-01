from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class HttpOAuthConfig(BaseModel):
    # Manual mode fields
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None

    # DCR mode fields
    issuer: str | None = None
    scopes: list[str] | None = None
    registration_token: str | None = None


class UpstreamStdioConfig(BaseModel):
    transport: str = "stdio"
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class UpstreamHttpConfig(BaseModel):
    transport: str = "http"
    url: str
    oauth: HttpOAuthConfig | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _reject_authorization_with_oauth(self) -> "UpstreamHttpConfig":
        if self.oauth is None or not self.headers:
            return self
        for key in self.headers:
            if key.strip().lower() == "authorization":
                raise ValueError(
                    "headers must not include 'Authorization' when oauth is "
                    "configured; the OAuth flow sets this header."
                )
        return self


class MaskingRuleConfig(BaseModel):
    tool_name: str
    field_path: str
    alias_prefix: str | None = None
    action: str = "mask"


class GuardrailConfig(BaseModel):
    tool_name: str = "*"
    argument_name: str = "*"
    match_type: str = "contains"
    pattern: str
    message: str = "Blocked by guardrail"


class InjectionConfig(BaseModel):
    tool_name: str = "*"
    argument_name: str
    value: str
    mode: str = "set"


class TargetConfig(BaseModel):
    upstream: UpstreamStdioConfig | UpstreamHttpConfig
    rules: list[MaskingRuleConfig] = Field(default_factory=list)
    guardrails: list[GuardrailConfig] = Field(default_factory=list)
    injections: list[InjectionConfig] = Field(default_factory=list)


class MultiTargetConfig(BaseModel):
    targets: dict[str, TargetConfig]
    web_port: int = 9473
    mcp_port: int = 9474
    oauth_port: int = 3131
    store_path: str = "~/.openmaskit/store.db"
    container_runtime: str | None = None  # Optional override for docker/podman/nerdctl/finch
