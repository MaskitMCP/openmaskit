"""Tests for the lazy traffic GET endpoint."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.traffic.buffer import TrafficBuffer
from openmaskit.traffic.store import TrafficEntry, TrafficStore
from openmaskit.web.app import create_app


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def traffic_store(tmp_path):
    s = await TrafficStore.create(tmp_path / "traffic.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def state(store, traffic_store):
    engine = MaskingEngine([], store, target_name="test")
    await engine.load_aliases()

    proxy_state = ProxyState()
    proxy_state.store = store
    proxy_state.traffic_store = traffic_store
    proxy_state.traffic_buffer = TrafficBuffer()
    target = TargetState(name="test", engine=engine, traffic_buffer=proxy_state.traffic_buffer)
    target.initialized = True
    proxy_state.targets["test"] = target
    return proxy_state


@pytest_asyncio.fixture
async def client(state):
    app = create_app(state)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _entry(target: str = "test", rid: str = "1", **kwargs) -> TrafficEntry:
    return TrafficEntry(
        ts=kwargs.get("ts", 1.0),
        target_name=target,
        status=kwargs.get("status", "ok"),
        tool_name=kwargs.get("tool_name", "echo"),
        request_id=rid,
        duration_ms=kwargs.get("duration_ms", 5),
        unmasked_args=kwargs.get("unmasked_args", '{"q":"prod-db"}'),
        unmasked_response=kwargs.get("unmasked_response", "real preview"),
        masked_args=kwargs.get("masked_args", '{"q":"host_1"}'),
        masked_response=kwargs.get("masked_response", "masked preview"),
    )


class TestTrafficRoute:
    @pytest.mark.anyio
    async def test_unknown_target_returns_404(self, client):
        resp = await client.get("/api/targets/nope/traffic")
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_empty_returns_empty_entries(self, client):
        resp = await client.get("/api/targets/test/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"entries": [], "has_more": False}

    @pytest.mark.anyio
    async def test_returns_persisted_entries(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid="a"), _entry(rid="b")])
        resp = await client.get("/api/targets/test/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["entries"]) == 2
        # Newest first.
        rids = [e["request_id"] for e in data["entries"]]
        assert rids == ["b", "a"]
        # Shape checks
        e = data["entries"][0]
        assert e["status"] == "ok"
        assert e["tool_name"] == "echo"
        assert e["unmasked_args"] == '{"q":"prod-db"}'
        assert e["masked_args"] == '{"q":"host_1"}'
        assert isinstance(e["id"], int)
        assert isinstance(e["ts"], float)

    @pytest.mark.anyio
    async def test_flushes_pending_buffer_before_query(self, client, state):
        """Entries that are only in the buffer must show up in the response."""
        state.traffic_buffer.append(_entry(rid="buffered"))
        resp = await client.get("/api/targets/test/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["request_id"] == "buffered"
        assert not state.traffic_buffer.has_pending

    @pytest.mark.anyio
    async def test_limit_param_caps_page_size(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid=str(i)) for i in range(10)])
        resp = await client.get("/api/targets/test/traffic?limit=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["entries"]) == 3
        assert data["has_more"] is True

    @pytest.mark.anyio
    async def test_has_more_false_on_last_page(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid=str(i)) for i in range(3)])
        resp = await client.get("/api/targets/test/traffic?limit=10")
        data = resp.json()
        assert len(data["entries"]) == 3
        assert data["has_more"] is False

    @pytest.mark.anyio
    async def test_before_cursor_pagination(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid=str(i)) for i in range(8)])

        page1 = (await client.get("/api/targets/test/traffic?limit=3")).json()
        assert len(page1["entries"]) == 3
        assert page1["has_more"] is True
        cursor = page1["entries"][-1]["id"]

        page2 = (await client.get(f"/api/targets/test/traffic?limit=3&before={cursor}")).json()
        assert len(page2["entries"]) == 3
        # No overlap
        ids_p1 = {e["id"] for e in page1["entries"]}
        ids_p2 = {e["id"] for e in page2["entries"]}
        assert ids_p1.isdisjoint(ids_p2)
        # Strictly older
        assert max(e["id"] for e in page2["entries"]) < cursor

    @pytest.mark.anyio
    async def test_scopes_by_target(self, client, traffic_store):
        await traffic_store.insert_many([
            _entry(target="test", rid="t1"),
            _entry(target="other", rid="o1"),
            _entry(target="test", rid="t2"),
        ])
        resp = await client.get("/api/targets/test/traffic")
        rids = [e["request_id"] for e in resp.json()["entries"]]
        assert set(rids) == {"t1", "t2"}

    @pytest.mark.anyio
    async def test_invalid_limit_falls_back_to_default(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid=str(i)) for i in range(3)])
        resp = await client.get("/api/targets/test/traffic?limit=abc")
        assert resp.status_code == 200
        assert len(resp.json()["entries"]) == 3

    @pytest.mark.anyio
    async def test_limit_clamped_to_max(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid=str(i)) for i in range(250)])
        resp = await client.get("/api/targets/test/traffic?limit=10000")
        assert resp.status_code == 200
        # Should cap at 200
        assert len(resp.json()["entries"]) == 200

    @pytest.mark.anyio
    async def test_invalid_before_treated_as_no_cursor(self, client, traffic_store):
        await traffic_store.insert_many([_entry(rid="a"), _entry(rid="b")])
        resp = await client.get("/api/targets/test/traffic?before=not-an-int")
        assert resp.status_code == 200
        assert len(resp.json()["entries"]) == 2

    @pytest.mark.anyio
    async def test_returns_blocked_entries(self, client, traffic_store):
        await traffic_store.insert_many([
            _entry(rid="b", status="blocked",
                   unmasked_response=None, masked_response="blocked: guardrail"),
        ])
        resp = await client.get("/api/targets/test/traffic")
        entries = resp.json()["entries"]
        assert entries[0]["status"] == "blocked"
        assert entries[0]["masked_response"] == "blocked: guardrail"
        assert entries[0]["unmasked_response"] is None

    @pytest.mark.anyio
    async def test_no_traffic_store_returns_empty(self, store):
        """If traffic_store is unset (defensive), endpoint returns empty payload."""
        engine = MaskingEngine([], store, target_name="t")
        await engine.load_aliases()
        ps = ProxyState()
        ps.store = store
        ps.traffic_store = None
        ps.traffic_buffer = None
        target = TargetState(name="t", engine=engine)
        target.initialized = True
        ps.targets["t"] = target

        app = create_app(ps)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/api/targets/t/traffic")
        assert resp.status_code == 200
        assert resp.json() == {"entries": [], "has_more": False}
