"""Tests for TrafficBuffer."""

from __future__ import annotations

import pytest

from maskit.traffic.buffer import TrafficBuffer
from maskit.traffic.store import TrafficEntry, TrafficStore


def _entry(target: str = "srv", rid: str = "1") -> TrafficEntry:
    return TrafficEntry(
        ts=1.0,
        target_name=target,
        status="ok",
        tool_name="echo",
        request_id=rid,
        duration_ms=1,
        unmasked_args='{"q":"x"}',
        unmasked_response="r",
        masked_args='{"q":"x"}',
        masked_response="r",
    )


@pytest.fixture
async def store(tmp_path):
    s = await TrafficStore.create(tmp_path / "traffic.db")
    yield s
    await s.close()


class TestTrafficBuffer:
    def test_append_increases_len(self):
        buf = TrafficBuffer()
        assert len(buf) == 0
        assert not buf.has_pending
        buf.append(_entry())
        assert len(buf) == 1
        assert buf.has_pending

    @pytest.mark.anyio
    async def test_flush_drains_to_store(self, store):
        buf = TrafficBuffer()
        buf.append(_entry(rid="a"))
        buf.append(_entry(rid="b"))

        written = await buf.flush(store)
        assert written == 2
        assert not buf.has_pending
        assert await store.count() == 2

    @pytest.mark.anyio
    async def test_flush_empty_is_noop(self, store):
        buf = TrafficBuffer()
        written = await buf.flush(store)
        assert written == 0
        assert await store.count() == 0

    @pytest.mark.anyio
    async def test_flush_handles_multiple_targets_in_one_batch(self, store):
        buf = TrafficBuffer()
        buf.append(_entry(target="srv-a", rid="1"))
        buf.append(_entry(target="srv-b", rid="2"))
        buf.append(_entry(target="srv-a", rid="3"))

        await buf.flush(store)
        a = await store.query("srv-a")
        b = await store.query("srv-b")
        assert {r.request_id for r in a} == {"1", "3"}
        assert {r.request_id for r in b} == {"2"}

    @pytest.mark.anyio
    async def test_flush_failure_drops_batch_and_recovers(self, store, monkeypatch):
        """If the store write raises, the batch is dropped (not retried forever)
        and the buffer is left empty so subsequent appends can land normally."""
        buf = TrafficBuffer()
        buf.append(_entry(rid="bad"))

        async def boom(_entries):
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(store, "insert_many", boom)

        written = await buf.flush(store)
        assert written == 0
        assert not buf.has_pending

        # New entries land normally after the failure
        monkeypatch.undo()
        buf.append(_entry(rid="good"))
        written = await buf.flush(store)
        assert written == 1
        rows = await store.query("srv")
        assert [r.request_id for r in rows] == ["good"]
