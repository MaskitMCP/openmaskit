"""Integration tests for the proxy core."""

import json

import anyio
import pytest

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import TargetState, run_proxy_for_target


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
    e = MaskingEngine(rules, store, target_name="test")
    await e.load_aliases()
    return e


@pytest.fixture
def target_state(engine):
    ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    target = TargetState(name="test", engine=engine, ds_read_send=ds_read_send, ds_read_recv=ds_read_recv)
    return target


class TestProxyRelay:
    @pytest.mark.anyio
    async def test_transparent_passthrough(self, engine):
        """Non-tool messages pass through unmodified after bootstrap."""
        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        target = TargetState(name="test", engine=engine, ds_read_send=ds_read_send, ds_read_recv=ds_read_recv)

        # Feed bootstrap responses
        await feed_bootstrap(us_read_send)

        # Close streams to end the relay
        await ds_read_send.aclose()
        await us_read_send.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(run_proxy_for_target, target, us_read_recv, us_write_send)

        # Bootstrap messages sent upstream: init, notifications/initialized, tools/list
        boot_init = await us_write_recv.receive()
        assert boot_init.message.root.method == "initialize"
        boot_notif = await us_write_recv.receive()
        assert boot_notif.message.root.method == "notifications/initialized"
        boot_tools = await us_write_recv.receive()
        assert boot_tools.message.root.method == "tools/list"

        # Tool schemas cached
        assert len(target.tool_schemas) == 1
        assert target.tool_schemas[0]["name"] == "get_db"

    @pytest.mark.anyio
    async def test_tool_call_masking(self, engine):
        """Tool call responses get masked, subsequent arguments get unmasked."""
        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        target = TargetState(name="test", engine=engine, ds_read_send=ds_read_send, ds_read_recv=ds_read_recv)

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

        # We need to collect dispatched responses — register waiters for the request IDs
        event5 = await target.response_dispatcher.register(5)
        event6 = await target.response_dispatcher.register(6)

        async with anyio.create_task_group() as tg:
            tg.start_soon(run_proxy_for_target, target, us_read_recv, us_write_send)

        # First response to the agent should have masked host
        resp1 = await target.response_dispatcher.collect(5)
        assert resp1 is not None
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
        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_read_send, us_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        us_write_send, us_write_recv = anyio.create_memory_object_stream[SessionMessage](10)

        target = TargetState(name="test", engine=engine, ds_read_send=ds_read_send, ds_read_recv=ds_read_recv)

        # Feed bootstrap responses
        await feed_bootstrap(us_read_send)

        # After bootstrap, tools should already be cached
        await ds_read_send.aclose()
        await us_read_send.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(run_proxy_for_target, target, us_read_recv, us_write_send)

        assert len(target.tool_schemas) == 1
        assert target.tool_schemas[0]["name"] == "get_db"
