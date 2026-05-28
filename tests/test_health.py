"""Tests for health check endpoint."""

import pytest
from collections import deque
from starlette.testclient import TestClient

from openmaskit.web.app import create_app
from openmaskit.proxy.core import ProxyState, TargetState, ResponseDispatcher
from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore


@pytest.fixture
async def health_app():
    """Create test app with mock proxy state."""
    # Create mock state with one healthy target
    store = await MaskingStore.create(":memory:")
    engine = MaskingEngine(store, "test-target")

    target = TargetState(
        name="test-target",
        engine=engine,
        tool_schemas=[{"name": "test_tool"}],
        hidden_tools=set(),
        response_dispatcher=ResponseDispatcher(),
        pending_tool_calls={},
        pending_requests={},
        initialized=True,
        init_result={"protocolVersion": "2024-11-05"},
    )

    state = ProxyState()
    state.targets = {"test-target": target}
    state.store = store
    state.target_manager = None
    state.callback_server = None
    state.config_target_ids = {"test-target"}
    state.mcp_port = 9474

    app = create_app(state)

    yield app

    await store.close()


@pytest.mark.asyncio
async def test_health_endpoint_healthy(health_app):
    """Health endpoint returns 200 when all systems healthy."""
    client = TestClient(health_app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["uptime_seconds"] > 0
    assert len(data["targets"]) == 1
    assert data["targets"][0]["name"] == "test-target"
    assert data["targets"][0]["status"] == "healthy"
    assert data["targets"][0]["initialized"] is True
    assert data["database"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_endpoint_degraded(health_app):
    """Health endpoint returns 200 with degraded status when some targets fail."""
    # Add unhealthy target
    engine = MaskingEngine(health_app.state.proxy_state.store, "broken-target")
    broken_target = TargetState(
        name="broken-target",
        engine=engine,
        tool_schemas=[],
        hidden_tools=set(),
        response_dispatcher=ResponseDispatcher(),
        pending_tool_calls={},
        pending_requests={},
        initialized=False,  # Not initialized
        init_result=None,
    )
    health_app.state.proxy_state.targets["broken-target"] = broken_target

    client = TestClient(health_app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "degraded"
    assert len(data["targets"]) == 2
    assert any(t["status"] == "unhealthy" for t in data["targets"])


@pytest.mark.asyncio
async def test_health_endpoint_unhealthy_no_db(health_app):
    """Health endpoint returns 503 when database unavailable."""
    # Remove database
    health_app.state.proxy_state.store = None

    client = TestClient(health_app)
    response = client.get("/health")

    assert response.status_code == 503
    data = response.json()

    assert data["status"] == "unhealthy"
    assert data["database"]["status"] == "unhealthy"


def test_json_logging_format():
    """JSON formatter produces valid JSON logs."""
    import logging
    from io import StringIO
    from openmaskit.logging_config import JSONFormatter

    # Create logger with JSON formatter
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())

    logger = logging.getLogger("test_json_logger")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log a message
    logger.info("Test message")

    # Parse output as JSON
    import json
    log_line = stream.getvalue().strip()
    log_data = json.loads(log_line)

    assert log_data["level"] == "INFO"
    assert log_data["message"] == "Test message"
    assert log_data["logger"] == "test_json_logger"
    assert "timestamp" in log_data
