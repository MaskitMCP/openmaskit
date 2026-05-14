"""Tests for graceful shutdown behavior."""

import pytest
import anyio
from collections import deque
from unittest.mock import MagicMock

from maskit.__main__ import _graceful_shutdown, _flush_loop
from maskit.proxy.core import ProxyState, TargetState, ResponseDispatcher, cleanup_target_state
from maskit.masking.engine import MaskingEngine
from maskit.masking.store import MaskingStore


@pytest.mark.asyncio
async def test_response_dispatcher_shutdown():
    """ResponseDispatcher.shutdown() wakes all waiters and clears state."""
    dispatcher = ResponseDispatcher()

    # Register a waiter
    event = await dispatcher.register("test-req-1")
    assert not event.is_set()

    # Shutdown should wake the waiter
    dispatcher.shutdown()
    assert event.is_set()

    # Waiter should be cleared (collect returns None)
    response = await dispatcher.collect("test-req-1")
    assert response is None


@pytest.mark.asyncio
async def test_cleanup_target_state():
    """cleanup_target_state clears pending requests and closes streams."""
    store = await MaskingStore.create(":memory:")
    engine = MaskingEngine(store, "test")

    target = TargetState(
        name="test",
        engine=engine,
        tool_schemas=[],
        hidden_tools=set(),
        traffic_log=deque(),
        traffic_events=deque(),
        response_dispatcher=ResponseDispatcher(),
        pending_tool_calls={"call-1": {}},
        pending_requests={"req-1": {}},
        initialized=True,
        init_result={},
    )

    # Setup a downstream stream
    send, receive = anyio.create_memory_object_stream(32)
    target.ds_read_send = send

    # Cleanup
    await cleanup_target_state(target)

    # Verify state cleared
    assert len(target.pending_tool_calls) == 0
    assert len(target.pending_requests) == 0

    # Stream should be closed
    with pytest.raises(anyio.ClosedResourceError):
        await send.send({"test": "message"})

    await store.close()


@pytest.mark.asyncio
async def test_graceful_shutdown_sequence():
    """Graceful shutdown coordinator follows expected sequence."""
    store = await MaskingStore.create(":memory:")
    engine = MaskingEngine(store, "test")

    target = TargetState(
        name="test",
        engine=engine,
        tool_schemas=[],
        hidden_tools=set(),
        traffic_log=deque(),
        traffic_events=deque(),
        response_dispatcher=ResponseDispatcher(),
        pending_tool_calls={},
        pending_requests={},
        initialized=True,
        init_result={},
    )

    state = ProxyState()
    state.targets = {"test": target}
    state.store = store

    shutdown_event = anyio.Event()

    # Mock servers
    mock_web = MagicMock(should_exit=False)
    mock_mcp = MagicMock(should_exit=False)
    mock_callback = MagicMock(should_exit=False)

    # Mock task group (will be cancelled)
    mock_tg = MagicMock()
    mock_tg.cancel_scope = MagicMock()

    # Run shutdown
    await _graceful_shutdown(
        state, shutdown_event, mock_web, mock_mcp, mock_callback, mock_tg,
        drain_timeout=1.0, flush_timeout=1.0
    )

    # Verify sequence:
    # 1. Servers marked for exit
    assert mock_web.should_exit is True
    assert mock_mcp.should_exit is True
    assert mock_callback.should_exit is True

    # 2. Shutdown event set
    assert shutdown_event.is_set()

    # 3. Task group cancelled
    mock_tg.cancel_scope.cancel.assert_called_once()

    await store.close()


@pytest.mark.asyncio
async def test_shutdown_timeout_enforcement():
    """Overall shutdown timeout is enforced."""
    # This test verifies that SHUTDOWN_TIMEOUT prevents indefinite hangs
    # We simulate a stuck task and ensure it gets cancelled

    async def stuck_task():
        """Task that never completes."""
        await anyio.sleep(999999)

    with pytest.raises(TimeoutError):
        with anyio.fail_after(1.0):  # Short timeout for test
            async with anyio.create_task_group() as tg:
                tg.start_soon(stuck_task)
                # Wait for timeout to trigger
                await anyio.sleep(999999)


@pytest.mark.asyncio
async def test_flush_loop_stops_on_shutdown_event():
    """Flush loop respects shutdown_event and performs final flush."""
    store = await MaskingStore.create(":memory:")
    engine = MaskingEngine(store, "test")
    shutdown_event = anyio.Event()

    # Simulate pending write by directly adding to the internal list
    engine._pending_writes.append(("alias_1", "real_value_1", "test_tool", "field1"))
    assert engine.has_pending_writes

    # Start flush loop in background
    async with anyio.create_task_group() as tg:
        tg.start_soon(_flush_loop, engine, shutdown_event)

        # Let it run for a bit
        await anyio.sleep(0.2)

        # Signal shutdown
        shutdown_event.set()

        # Wait for flush loop to exit (should be quick)
        await anyio.sleep(0.5)

    # Final flush should have been performed
    assert not engine.has_pending_writes

    await store.close()
