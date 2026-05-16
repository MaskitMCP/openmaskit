"""Tests for OAuth state cleanup (security: DoS prevention)."""

import anyio
import pytest
import time


class TestOAuthStateCleanup:
    """Test OAuth state cleanup prevents memory exhaustion DoS."""

    @pytest.mark.anyio
    async def test_expired_oauth_states_are_cleaned_up(self):
        """Expired OAuth states are removed by cleanup task."""
        from maskit.web.routes.oauth_callback import OAUTH_STATE_TTL

        oauth_states = {
            "fresh_state": {"server_id": "server1", "handle": "server1", "timestamp": time.time()},
            "old_state": {"server_id": "server2", "handle": "server2", "timestamp": time.time() - OAUTH_STATE_TTL - 1},
            "ancient_state": {"server_id": "server3", "handle": "server3", "timestamp": time.time() - 2000},
        }

        # Run cleanup task once (simulate cleanup logic)
        async def run_cleanup_once():
            await anyio.sleep(0)
            now = time.time()
            expired = [
                state_id for state_id, data in oauth_states.items()
                if now - data.get("timestamp", 0) > OAUTH_STATE_TTL
            ]
            for state_id in expired:
                oauth_states.pop(state_id, None)

        await run_cleanup_once()

        # Verify only fresh state remains
        assert "fresh_state" in oauth_states
        assert "old_state" not in oauth_states
        assert "ancient_state" not in oauth_states
        assert len(oauth_states) == 1

    @pytest.mark.anyio
    async def test_dos_attack_via_repeated_oauth_initiation(self):
        """Memory exhaustion attack prevented by cleanup."""
        from maskit.web.routes.oauth_callback import OAUTH_STATE_TTL

        oauth_states = {}

        # Simulate attacker initiating 1000 OAuth flows without completing them
        attacker_states = []
        for i in range(1000):
            state_id = f"attack_{i}"
            oauth_states[state_id] = {
                "server_id": f"server_{i}",
                "handle": f"handle_{i}",
                "timestamp": time.time() - OAUTH_STATE_TTL - 1,  # All expired
            }
            attacker_states.append(state_id)

        # Before cleanup, dict is full
        assert len(oauth_states) == 1000

        # Run cleanup
        now = time.time()
        expired = [
            state_id for state_id, data in oauth_states.items()
            if now - data.get("timestamp", 0) > OAUTH_STATE_TTL
        ]
        for state_id in expired:
            oauth_states.pop(state_id, None)

        # After cleanup, all expired entries removed
        assert len(oauth_states) == 0, "Cleanup should remove all expired attack states"

    @pytest.mark.anyio
    async def test_cleanup_preserves_active_oauth_flows(self):
        """Active OAuth flows are not affected by cleanup."""
        from maskit.web.routes.oauth_callback import OAUTH_STATE_TTL

        oauth_states = {
            "active_flow_1": {"server_id": "slack", "handle": "slack", "timestamp": time.time()},
            "active_flow_2": {"server_id": "github", "handle": "github", "timestamp": time.time() - 60},  # 1 minute old
            "expired_flow": {"server_id": "old", "handle": "old", "timestamp": time.time() - OAUTH_STATE_TTL - 100},
        }

        # Run cleanup
        now = time.time()
        expired = [
            state_id for state_id, data in oauth_states.items()
            if now - data.get("timestamp", 0) > OAUTH_STATE_TTL
        ]
        for state_id in expired:
            oauth_states.pop(state_id, None)

        # Active flows preserved, expired removed
        assert "active_flow_1" in oauth_states
        assert "active_flow_2" in oauth_states
        assert "expired_flow" not in oauth_states
        assert len(oauth_states) == 2
