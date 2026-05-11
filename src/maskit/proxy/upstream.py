"""Upstream transport: connection to the real MCP server."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TextIO

import anyio
import httpx
import uvicorn

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from maskit.models import UpstreamHttpConfig, UpstreamStdioConfig


@asynccontextmanager
async def connect_upstream(
    upstream: UpstreamStdioConfig | UpstreamHttpConfig,
    store_path: str = "~/.maskit/store.db",
    errlog: TextIO = sys.stderr,
    extra_env: dict[str, str] | None = None,
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

            oauth_store_path = Path(store_path).expanduser().parent / "oauth_tokens.json"
            provider, callback_server = create_oauth_provider(
                upstream.url, upstream.oauth, oauth_store_path
            )

            # Start the callback server so it can receive the OAuth redirect
            callback_app = callback_server.create_app()
            uvicorn_config = uvicorn.Config(
                callback_app,
                host="127.0.0.1",
                port=upstream.oauth.callback_port,
                log_level="warning",
                log_config=None,
            )
            callback_web_server = uvicorn.Server(uvicorn_config)

            async with anyio.create_task_group() as oauth_tg:
                oauth_tg.start_soon(callback_web_server.serve)
                await anyio.sleep(0.3)  # Let server bind

                http_client = httpx.AsyncClient(auth=provider)
                async with http_client:
                    async with streamable_http_client(
                        upstream.url, http_client=http_client
                    ) as (read_stream, write_stream, _get_session_id):
                        yield read_stream, write_stream

                callback_web_server.should_exit = True
                oauth_tg.cancel_scope.cancel()
        else:
            # No OAuth, plain HTTP connection
            async with streamable_http_client(upstream.url) as (
                read_stream,
                write_stream,
                _get_session_id,
            ):
                yield read_stream, write_stream

    else:
        raise ValueError(f"Unknown upstream config type: {type(upstream)}")
