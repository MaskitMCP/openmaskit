"""Regression tests: the MCP endpoint at :9474 must never leak unmasked data.

The dashboard's ``/api/targets/{name}/tools/call`` endpoint intentionally
attaches the alias map so the UI can render hover-overs. The agent-facing MCP
endpoint at :9474 must NEVER do that. Same for unmasked-preview fields. These
tests pin those invariants so a future change can't accidentally bolt the alias
dict (or any other unmasked-data field) onto agent-facing responses.
"""

from __future__ import annotations

import json

import anyio
import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.proxy.http_downstream import create_mcp_app


# Sentinel "secrets" we plant in engine.alias_cache. If any of these strings
# appears in an MCP-endpoint response body, the proxy has leaked unmasked data.
SECRET_HOST = "prod-db.internal.acme.corp"
SECRET_TOKEN = "sk-live-9af3c2b1e7d4f5a6"
ALIAS_HOST = "host_42"
ALIAS_TOKEN = "token_42"


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def state(store):
    engine = MaskingEngine([], store, target_name="test")
    await engine.load_aliases()
    # Plant the alias cache so we can detect leaks.
    engine.alias_cache[ALIAS_HOST] = SECRET_HOST
    engine.alias_cache[ALIAS_TOKEN] = SECRET_TOKEN

    state = ProxyState()
    state.mcp_port = 9474
    ds_read_send, ds_read_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](32)
    target = TargetState(
        name="test",
        engine=engine,
        ds_read_send=ds_read_send,
        ds_read_recv=ds_read_recv,
    )
    target.initialized = True
    target.init_result = {
        "protocolVersion": "2025-03-26",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "test", "version": "0.1"},
    }
    state.targets["test"] = target
    return state


def _walk_keys(obj):
    """Yield every key name appearing anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_keys(item)


def _flat_string_repr(obj) -> str:
    """Flatten an object to a single string for substring leak checks."""
    return json.dumps(obj, default=str)


class TestMcpEndpointNoLeak:
    """Pin the contract: nothing on :9474 may carry alias maps or unmasked data."""

    @pytest.mark.anyio
    async def test_initialize_response_has_no_aliases_key(self, state):
        """The cached initialize result must not be wrapped with an alias map."""
        app = create_mcp_app(state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post(
                "/test/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "aliases" not in set(_walk_keys(data))

    @pytest.mark.anyio
    async def test_forwarded_response_has_no_aliases_key(self, state):
        """A tool-call response routed through the dispatcher must not gain an alias map."""
        app = create_mcp_app(state)

        async def feed_response():
            # Wait for the endpoint to register a waiter, then dispatch a
            # post-masking response (i.e. one that contains the *alias*, not
            # the real value — the relay would have masked it already).
            await anyio.sleep(0.05)
            target = state.targets["test"]
            response = JSONRPCMessage.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"Connected to {ALIAS_HOST}"}
                        ],
                        "isError": False,
                    },
                }
            )
            await target.response_dispatcher.dispatch(7, SessionMessage(response))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            async with anyio.create_task_group() as tg:
                tg.start_soon(feed_response)
                resp = await c.post(
                    "/test/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {"name": "anything", "arguments": {}},
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        assert "aliases" not in set(_walk_keys(data))

    @pytest.mark.anyio
    async def test_response_does_not_contain_unmasked_values(self, state):
        """Even if a careless future change attached engine.alias_cache.values()
        to a response, this would catch it — the secret strings themselves must
        never appear in the MCP-endpoint response body."""
        app = create_mcp_app(state)

        async def feed_response():
            await anyio.sleep(0.05)
            target = state.targets["test"]
            response = JSONRPCMessage.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "result": {
                        "content": [{"type": "text", "text": f"OK: {ALIAS_HOST}"}],
                        "isError": False,
                    },
                }
            )
            await target.response_dispatcher.dispatch(8, SessionMessage(response))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            async with anyio.create_task_group() as tg:
                tg.start_soon(feed_response)
                resp = await c.post(
                    "/test/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 8,
                        "method": "tools/call",
                        "params": {"name": "anything", "arguments": {}},
                    },
                )

        body = resp.text
        assert SECRET_HOST not in body
        assert SECRET_TOKEN not in body
        # The masked alias may legitimately appear in the response (it was the
        # post-masking output the upstream-relay produced).
        assert ALIAS_HOST in body

    @pytest.mark.anyio
    async def test_response_does_not_contain_traffic_preview_fields(self, state):
        """Traffic-buffer entries (with unmasked previews) must not leak through the MCP endpoint."""
        from openmaskit.traffic.buffer import TrafficBuffer
        from openmaskit.traffic.store import TrafficEntry

        app = create_mcp_app(state)
        target = state.targets["test"]
        target.traffic_buffer = TrafficBuffer()

        async def feed_response():
            await anyio.sleep(0.05)
            # Plant a traffic entry carrying unmasked content to make sure it can't escape.
            target.traffic_buffer.append(TrafficEntry(
                ts=1.0,
                target_name="test",
                status="ok",
                tool_name="anything",
                request_id="trace-1",
                duration_ms=1,
                unmasked_args=None,
                unmasked_response=f"raw secret was {SECRET_HOST}",
                masked_args=None,
                masked_response=f"masked was {ALIAS_HOST}",
            ))
            response = JSONRPCMessage.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "result": {
                        "content": [{"type": "text", "text": f"hi {ALIAS_HOST}"}],
                        "isError": False,
                    },
                }
            )
            await target.response_dispatcher.dispatch(9, SessionMessage(response))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            async with anyio.create_task_group() as tg:
                tg.start_soon(feed_response)
                resp = await c.post(
                    "/test/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 9,
                        "method": "tools/call",
                        "params": {"name": "anything", "arguments": {}},
                    },
                )

        body = resp.text
        assert SECRET_HOST not in body
        assert "raw secret" not in body
        data = resp.json()
        keys = set(_walk_keys(data))
        assert "unmasked_response" not in keys
        assert "unmasked_args" not in keys
        assert "traffic_log" not in keys
        assert "alias_cache" not in keys
        # And the raw secret must absolutely not appear anywhere.
        assert SECRET_HOST not in resp.text

    @pytest.mark.anyio
    async def test_invalid_request_response_has_no_aliases_key(self, state):
        """Even error responses (parse error, invalid request) must not leak."""
        app = create_mcp_app(state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            # Malformed JSON
            resp = await c.post(
                "/test/mcp",
                content=b"{not valid",
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert "aliases" not in set(_walk_keys(data))
        assert SECRET_HOST not in resp.text
