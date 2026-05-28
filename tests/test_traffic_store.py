"""Tests for TrafficStore."""

from __future__ import annotations

import pytest

from openmaskit.traffic.store import TrafficEntry, TrafficStore


@pytest.fixture
async def store(tmp_path):
    s = await TrafficStore.create(tmp_path / "traffic.db")
    yield s
    await s.close()


def _entry(
    target: str = "srv",
    ts: float = 1.0,
    status: str = "ok",
    tool: str = "echo",
    rid: str = "1",
    unmasked_args: str | None = '{"q":"prod-db.internal.net"}',
    unmasked_response: str | None = "real content",
    masked_args: str | None = '{"q":"host_1"}',
    masked_response: str | None = "masked content",
    duration_ms: int = 12,
) -> TrafficEntry:
    return TrafficEntry(
        ts=ts,
        target_name=target,
        status=status,
        tool_name=tool,
        request_id=rid,
        duration_ms=duration_ms,
        unmasked_args=unmasked_args,
        unmasked_response=unmasked_response,
        masked_args=masked_args,
        masked_response=masked_response,
    )


class TestTrafficStore:
    @pytest.mark.anyio
    async def test_insert_and_query(self, store):
        await store.insert_many([_entry()])
        rows = await store.query("srv")
        assert len(rows) == 1
        r = rows[0]
        assert r.id is not None
        assert r.target_name == "srv"
        assert r.tool_name == "echo"
        assert r.status == "ok"
        assert r.unmasked_args == '{"q":"prod-db.internal.net"}'
        assert r.unmasked_response == "real content"
        assert r.masked_args == '{"q":"host_1"}'
        assert r.masked_response == "masked content"

    @pytest.mark.anyio
    async def test_encryption_at_rest(self, store, tmp_path):
        """Raw bytes in the DB file must not contain the unmasked plaintext."""
        await store.insert_many(
            [_entry(unmasked_args='{"secret":"hunter2"}', unmasked_response="apikey_abc123")]
        )
        # Force WAL flush so content lands in the main file
        await store._db.commit()
        await store._db.execute("PRAGMA wal_checkpoint(FULL)")
        await store._db.commit()

        raw = (tmp_path / "traffic.db").read_bytes()
        assert b"hunter2" not in raw
        assert b"apikey_abc123" not in raw

    @pytest.mark.anyio
    async def test_roundtrip_survives_reopen(self, tmp_path):
        path = tmp_path / "traffic.db"
        s1 = await TrafficStore.create(path)
        await s1.insert_many([_entry(unmasked_args='{"k":"v"}', unmasked_response="resp")])
        await s1.close()

        s2 = await TrafficStore.create(path)
        rows = await s2.query("srv")
        assert len(rows) == 1
        assert rows[0].unmasked_args == '{"k":"v"}'
        assert rows[0].unmasked_response == "resp"
        await s2.close()

    @pytest.mark.anyio
    async def test_query_orders_newest_first(self, store):
        await store.insert_many([
            _entry(rid="a", ts=1.0),
            _entry(rid="b", ts=2.0),
            _entry(rid="c", ts=3.0),
        ])
        rows = await store.query("srv")
        assert [r.request_id for r in rows] == ["c", "b", "a"]

    @pytest.mark.anyio
    async def test_query_pagination_before_id(self, store):
        await store.insert_many([_entry(rid=str(i), ts=float(i)) for i in range(10)])

        page1 = await store.query("srv", limit=4)
        assert len(page1) == 4
        assert [r.request_id for r in page1] == ["9", "8", "7", "6"]

        cursor = page1[-1].id
        page2 = await store.query("srv", limit=4, before_id=cursor)
        assert [r.request_id for r in page2] == ["5", "4", "3", "2"]

        page3 = await store.query("srv", limit=4, before_id=page2[-1].id)
        assert [r.request_id for r in page3] == ["1", "0"]

    @pytest.mark.anyio
    async def test_query_filters_by_target(self, store):
        await store.insert_many([
            _entry(target="srv-a", rid="a1"),
            _entry(target="srv-b", rid="b1"),
            _entry(target="srv-a", rid="a2"),
        ])
        rows_a = await store.query("srv-a")
        rows_b = await store.query("srv-b")
        assert {r.request_id for r in rows_a} == {"a1", "a2"}
        assert {r.request_id for r in rows_b} == {"b1"}

    @pytest.mark.anyio
    async def test_null_unmasked_fields(self, store):
        """A blocked or error row may have no unmasked response."""
        await store.insert_many([
            _entry(
                status="blocked",
                unmasked_args='{"q":"bad"}',
                unmasked_response=None,
                masked_response=None,
            )
        ])
        rows = await store.query("srv")
        assert rows[0].status == "blocked"
        assert rows[0].unmasked_response is None
        assert rows[0].masked_response is None
        assert rows[0].unmasked_args == '{"q":"bad"}'

    @pytest.mark.anyio
    async def test_enforce_row_cap_drops_oldest(self, store):
        await store.insert_many([_entry(rid=str(i), ts=float(i)) for i in range(20)])
        assert await store.count() == 20

        deleted = await store.enforce_row_cap(10)
        assert deleted == 10
        assert await store.count() == 10

        rows = await store.query("srv", limit=100)
        # Newest 10 survived
        assert {r.request_id for r in rows} == {str(i) for i in range(10, 20)}

    @pytest.mark.anyio
    async def test_enforce_row_cap_noop_when_under_cap(self, store):
        await store.insert_many([_entry(rid=str(i)) for i in range(5)])
        deleted = await store.enforce_row_cap(100)
        assert deleted == 0
        assert await store.count() == 5

    @pytest.mark.anyio
    async def test_enforce_row_cap_zero_is_noop(self, store):
        """Defensive: cap of 0 (or negative) should not wipe the table."""
        await store.insert_many([_entry()])
        deleted = await store.enforce_row_cap(0)
        assert deleted == 0
        assert await store.count() == 1

    @pytest.mark.anyio
    async def test_insert_many_empty_is_noop(self, store):
        await store.insert_many([])
        assert await store.count() == 0

    @pytest.mark.anyio
    async def test_status_blocked_persists(self, store):
        await store.insert_many([_entry(status="blocked", rid="b")])
        rows = await store.query("srv")
        assert rows[0].status == "blocked"
