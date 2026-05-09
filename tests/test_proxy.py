"""Integration tests for the proxy core."""

import json

import anyio
import pytest

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import ProxyState, run_proxy


def make_request(method: str, params: dict | None = None, req_id: int = 1) -> SessionMessage:
    msg = JSONRPCMessage.model_validate({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params,
    })
    return SessionMessage(msg)


def make_response(result: dict, req_id: int | str = 1) -> SessionMessage:
    msg = JSONRPCMessage.model_validate({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    })
    return SessionMessage(msg)


BOOTSTRAP_INIT_RESPONSE = make_response(
    {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "test", "version": "0.1"}},
    req_id="__maskit_init__",
)
BOOTSTRAP_TOOLS_RESPONSE = make_response(
    {"tools": [{"name": "get_db", "description": "Get DB", "inputSchema": {"type": "object"}}]},
    req_id="__maskit_tools_list__",
)


async def feed_bootstrap(us_read_send):
    """Feed the expected bootstrap responses into the upstream read stream."""
    await us_read_send.send(BOOTSTRAP_INIT_RESPONSE)
    await us_read_send.send(BOOTSTRAP_TOOLS_RESPONSE)


@pytest.fixture
def rules():
    return [
        MaskingRule(tool_name="get_db", field_path="host", alias_prefix="host"),
    ]


@pytest.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest.fixture
async def engine(rules, store):
    e = MaskingEngine(rules, store)
    await e.load_aliases()
    return e


class TestProxyRelay:
    @pytest.mark.anyio
    async def test_transparent_passthrough(self, engine):
        """Non-tool messages pass through unmodified after bootstrap."""
        state = ProxyState(engine=engine)

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        ds_write_send, ds_write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        # Feed bootstrap responses
        await feed_bootstrap(us_read_send)

        # Host sends initialize — since we already bootstrapped, it gets a synthesized response
        init_req = make_request("initialize", {"capabilities": {}}, req_id=1)
        await ds_read_send.send(init_req)
        await ds_read_send.aclose()
        await us_read_send.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(
                run_proxy, ds_read_recv, ds_write_send, us_read_recv, us_write_send, state
            )

        # The initialize was NOT forwarded upstream (synthesized locally)
        # The only messages upstream should be our bootstrap init + tools/list
        boot_init = await us_write_recv.receive()
        assert boot_init.message.root.method == "initialize"
        # notifications/initialized
        boot_notif = await us_write_recv.receive()
        assert boot_notif.message.root.method == "notifications/initialized"
        # tools/list
        boot_tools = await us_write_recv.receive()
        assert boot_tools.message.root.method == "tools/list"

        # Host gets the synthesized response
        response = await ds_write_recv.receive()
        assert response.message.root.result["capabilities"]["tools"] == {}

    @pytest.mark.anyio
    async def test_tool_call_masking(self, engine):
        """Tool call responses get masked, subsequent arguments get unmasked."""
        state = ProxyState(engine=engine)

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        ds_write_send, ds_write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        # Feed bootstrap responses
        await feed_bootstrap(us_read_send)

        # Agent sends tools/call request
        call_req = make_request("tools/call", {"name": "get_db", "arguments": {}}, req_id=5)
        await ds_read_send.send(call_req)

        # Upstream responds with real host
        call_resp = make_response({
            "content": [{"type": "text", "text": json.dumps({"host": "prod-db.internal.net", "port": 5432})}]
        }, req_id=5)
        await us_read_send.send(call_resp)

        # Agent sends another request using the masked value
        call_req2 = make_request("tools/call", {
            "name": "get_db",
            "arguments": {"target": "host_1"}
        }, req_id=6)
        await ds_read_send.send(call_req2)
        await ds_read_send.aclose()

        # Second upstream response
        call_resp2 = make_response({"content": [{"type": "text", "text": "ok"}]}, req_id=6)
        await us_read_send.send(call_resp2)
        await us_read_send.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(
                run_proxy, ds_read_recv, ds_write_send, us_read_recv, us_write_send, state
            )

        # First response to the agent should have masked host
        resp1 = await ds_write_recv.receive()
        content = json.loads(resp1.message.root.result["content"][0]["text"])
        assert content["host"] == "host_1"
        assert content["port"] == 5432

        # Collect all messages sent upstream
        all_upstream = []
        try:
            while True:
                all_upstream.append(us_write_recv.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            pass

        # Filter to tools/call requests
        calls_forwarded = [
            m for m in all_upstream
            if isinstance(m.message.root, JSONRPCRequest) and m.message.root.method == "tools/call"
        ]

        assert len(calls_forwarded) == 2
        # Second request forwarded upstream should have unmasked value
        assert calls_forwarded[1].message.root.params["arguments"]["target"] == "prod-db.internal.net"

    @pytest.mark.anyio
    async def test_tools_list_cached(self, engine):
        """tools/list responses get cached in state for the Web UI."""
        state = ProxyState(engine=engine)

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        ds_write_send, ds_write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        # Feed bootstrap responses
        await feed_bootstrap(us_read_send)

        # After bootstrap, tools should already be cached
        await ds_read_send.aclose()
        await us_read_send.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(
                run_proxy, ds_read_recv, ds_write_send, us_read_recv, us_write_send, state
            )

        assert len(state.tool_schemas) == 1
        assert state.tool_schemas[0]["name"] == "get_db"
