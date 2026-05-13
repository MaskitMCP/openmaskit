"""Upstream transport: connection to the real MCP server."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

import httpx

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from maskit.models import UpstreamHttpConfig, UpstreamStdioConfig

if TYPE_CHECKING:
    from maskit.oauth.handler import OAuthCallbackServer

logger = logging.getLogger(__name__)


@asynccontextmanager
async def connect_upstream(
    upstream: UpstreamStdioConfig | UpstreamHttpConfig,
    store_path: str = "~/.maskit/store.db",
    errlog: TextIO = sys.stderr,
    extra_env: dict[str, str] | None = None,
    server_id: str | None = None,
    callback_server: "OAuthCallbackServer | None" = None,
):
    """Connect to the upstream MCP server. Yields (read_stream, write_stream)."""
    if isinstance(upstream, UpstreamStdioConfig):
        env = dict(upstream.env) if upstream.env else {}
        if extra_env:
            env.update(extra_env)

        params = StdioServerParameters(
            command=upstream.command,
            args=upstream.args,
            env=env if env else None,
        )
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            yield read_stream, write_stream

    elif isinstance(upstream, UpstreamHttpConfig):
        if upstream.oauth:
            from maskit.oauth.handler import create_oauth_provider

            oauth_dir = Path(store_path).expanduser().parent / "oauth"
            oauth_dir.mkdir(parents=True, exist_ok=True)
            name = server_id or upstream.url.replace("https://", "").replace("/", "_")
            oauth_store_path = oauth_dir / f"{name}.json"

            provider = create_oauth_provider(
                upstream.url,
                upstream.oauth,
                oauth_store_path,
                callback_server=callback_server,
            )

            http_client = httpx.AsyncClient(auth=provider)
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream

        else:
            async with streamable_http_client(upstream.url) as (
                read_stream,
                write_stream,
                _get_session_id,
            ):
                yield read_stream, write_stream

    else:
        raise ValueError(f"Unknown upstream config type: {type(upstream)}")
