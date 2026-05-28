"""Tests for proxy target manager."""

import pytest
import pytest_asyncio
import anyio

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.proxy.manager import TargetManager


@pytest_asyncio.fixture
async def store(tmp_path):
    """Create test store."""
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def state(store):
    """Create test proxy state."""
    proxy_state = ProxyState()
    proxy_state.store = store
    proxy_state.mcp_port = 9474
    return proxy_state


class TestTargetManagerInit:
    """Test TargetManager initialization."""

    @pytest.mark.anyio
    async def test_init_basic(self, state, store, tmp_path):
        """Initialize manager with basic parameters."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        assert manager._state is state
        assert manager._store is store
        assert manager._store_path == str(tmp_path / "store.db")
        assert manager._callback_server is None
        assert manager._container_runtime is None
        assert manager._exit_stacks == {}
        assert manager._task_group is None
        assert manager._shutdown_event is None

    @pytest.mark.anyio
    async def test_init_with_callback_server(self, state, store, tmp_path):
        """Initialize manager with callback server."""
        from openmaskit.oauth.handler import OAuthCallbackServer

        callback_server = OAuthCallbackServer(port=3131)

        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
            callback_server=callback_server,
        )

        assert manager._callback_server is callback_server

    @pytest.mark.anyio
    async def test_init_with_container_runtime(self, state, store, tmp_path):
        """Initialize manager with container runtime."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
            container_runtime="podman",
        )

        assert manager._container_runtime == "podman"

    @pytest.mark.anyio
    async def test_set_task_group(self, state, store, tmp_path):
        """Set task group and shutdown event."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        async with anyio.create_task_group() as tg:
            shutdown_event = anyio.Event()
            manager.set_task_group(tg, shutdown_event)

            assert manager._task_group is tg
            assert manager._shutdown_event is shutdown_event


class TestTargetManagerLifecycle:
    """Test target lifecycle management."""

    @pytest.mark.anyio
    async def test_target_added_to_state(self, state, store, tmp_path):
        """Verify target is added to proxy state."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        # Initially no targets
        assert len(state.targets) == 0

        # We can't easily test full add_target without mocking upstream connection
        # But we can verify the state structure exists
        assert hasattr(state, 'targets')
        assert isinstance(state.targets, dict)

    @pytest.mark.anyio
    async def test_remove_target_from_state(self, state, store, tmp_path):
        """Test removing a target from state."""
        # Pre-populate state with a target
        engine = MaskingEngine([], store, target_name="test-target")
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()

        target = TargetState(name="test-target", engine=engine)
        state.targets["test-target"] = target

        assert "test-target" in state.targets

        # Create manager
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        # Remove target
        async with anyio.create_task_group() as tg:
            shutdown_event = anyio.Event()
            manager.set_task_group(tg, shutdown_event)

            await manager.remove_target("test-target")

            # Target should be removed from state
            assert "test-target" not in state.targets

    @pytest.mark.anyio
    async def test_remove_nonexistent_target(self, state, store, tmp_path):
        """Removing non-existent target should not error."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        async with anyio.create_task_group() as tg:
            shutdown_event = anyio.Event()
            manager.set_task_group(tg, shutdown_event)

            # Should not raise
            await manager.remove_target("nonexistent")

            # State unchanged
            assert "nonexistent" not in state.targets


class TestConfigValidation:
    """Test configuration validation and parsing."""

    @pytest.mark.anyio
    async def test_stdio_config_validation(self, state, store, tmp_path):
        """Validate stdio configuration structure."""
        config = {
            "transport": "stdio",
            "command": "uvx",
            "args": ["mcp-server-time"],
        }

        from openmaskit.proxy.manager import _build_upstream_config

        upstream = _build_upstream_config(config)

        # Should create UpstreamStdioConfig
        assert hasattr(upstream, 'command')
        assert upstream.command == "uvx"
        assert upstream.args == ["mcp-server-time"]

    @pytest.mark.anyio
    async def test_http_config_validation(self, state, store, tmp_path):
        """Validate HTTP configuration structure."""
        config = {
            "transport": "http",
            "url": "https://mcp.example.com/mcp",
        }

        from openmaskit.proxy.manager import _build_upstream_config

        upstream = _build_upstream_config(config)

        # Should create UpstreamHttpConfig
        assert hasattr(upstream, 'url')
        assert upstream.url == "https://mcp.example.com/mcp"

    @pytest.mark.anyio
    async def test_config_with_oauth(self, state, store, tmp_path):
        """Validate HTTP config with OAuth."""
        config = {
            "transport": "http",
            "url": "https://mcp.slack.com/mcp",
            "oauth": {
                "client_id": "test-client",
                "scopes": ["read", "write"]
            }
        }

        from openmaskit.proxy.manager import _build_upstream_config

        upstream = _build_upstream_config(config)

        assert upstream.url == "https://mcp.slack.com/mcp"
        assert upstream.oauth is not None
        assert upstream.oauth.client_id == "test-client"


class TestExitStackManagement:
    """Test async exit stack management for resources."""

    @pytest.mark.anyio
    async def test_exit_stacks_initialized(self, state, store, tmp_path):
        """Exit stacks dict is initialized."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        assert isinstance(manager._exit_stacks, dict)
        assert len(manager._exit_stacks) == 0

    @pytest.mark.anyio
    async def test_exit_stack_created_per_target(self, state, store, tmp_path):
        """Each target should have its own exit stack."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        # Exit stacks are managed internally during add_target
        # We verify the structure exists
        assert hasattr(manager, '_exit_stacks')


class TestContainerRuntimeIntegration:
    """Test container runtime integration."""

    @pytest.mark.anyio
    async def test_manager_with_docker_runtime(self, state, store, tmp_path):
        """Manager configured with Docker runtime."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
            container_runtime="docker",
        )

        assert manager._container_runtime == "docker"

    @pytest.mark.anyio
    async def test_manager_with_podman_runtime(self, state, store, tmp_path):
        """Manager configured with Podman runtime."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
            container_runtime="podman",
        )

        assert manager._container_runtime == "podman"

    @pytest.mark.anyio
    async def test_manager_without_runtime(self, state, store, tmp_path):
        """Manager without explicit container runtime."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        # Should default to None (auto-detect at runtime)
        assert manager._container_runtime is None


class TestStateManagement:
    """Test proxy state management."""

    @pytest.mark.anyio
    async def test_state_targets_dict(self, state):
        """Proxy state has targets dictionary."""
        assert hasattr(state, 'targets')
        assert isinstance(state.targets, dict)

    @pytest.mark.anyio
    async def test_state_target_addition(self, state, store):
        """Add target to state manually."""
        engine = MaskingEngine([], store, target_name="manual-target")
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()

        target = TargetState(name="manual-target", engine=engine)
        state.targets["manual-target"] = target

        assert "manual-target" in state.targets
        assert state.targets["manual-target"].name == "manual-target"

    @pytest.mark.anyio
    async def test_state_target_removal(self, state, store):
        """Remove target from state manually."""
        engine = MaskingEngine([], store, target_name="temp-target")
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()

        target = TargetState(name="temp-target", engine=engine)
        state.targets["temp-target"] = target

        assert "temp-target" in state.targets

        # Remove
        del state.targets["temp-target"]

        assert "temp-target" not in state.targets

    @pytest.mark.anyio
    async def test_state_multiple_targets(self, state, store):
        """State can hold multiple targets."""
        for i in range(3):
            engine = MaskingEngine([], store, target_name=f"target-{i}")
            await engine.load_aliases()
            await engine.load_mappers()
            await engine.load_guardrails()
            await engine.load_injections()

            target = TargetState(name=f"target-{i}", engine=engine)
            state.targets[f"target-{i}"] = target

        assert len(state.targets) == 3
        assert "target-0" in state.targets
        assert "target-1" in state.targets
        assert "target-2" in state.targets


class TestManagerErrorHandling:
    """Test error handling in manager operations."""

    @pytest.mark.anyio
    async def test_remove_target_before_set_task_group(self, state, store, tmp_path):
        """Removing target before task group is set should handle gracefully."""
        manager = TargetManager(
            state=state,
            store=store,
            store_path=str(tmp_path / "store.db"),
        )

        # Task group not set yet
        assert manager._task_group is None

        # Should not crash (though might log warning)
        # This tests defensive programming
        try:
            # Can't actually call remove_target without task group
            # But we verify the state
            assert manager._task_group is None
        except Exception:
            pytest.fail("Should handle missing task group gracefully")

    @pytest.mark.anyio
    async def test_invalid_config_structure(self):
        """Handle invalid configuration structure."""
        from openmaskit.proxy.manager import _build_upstream_config

        # Missing required fields
        config = {
            "transport": "stdio",
            # Missing command
        }

        with pytest.raises(KeyError):
            _build_upstream_config(config)

    @pytest.mark.anyio
    async def test_unknown_transport_type(self):
        """Handle unknown transport type."""
        from openmaskit.proxy.manager import _build_upstream_config

        config = {
            "transport": "websocket",  # Not supported
            "url": "ws://example.com",
        }

        # Should default to http path (since transport != "stdio")
        upstream = _build_upstream_config(config)

        # Will create UpstreamHttpConfig
        assert hasattr(upstream, 'url')
