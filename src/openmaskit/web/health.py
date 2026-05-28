"""Health check endpoint for monitoring and orchestration."""

import time
from typing import Literal

from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse

from openmaskit.proxy.core import ProxyState


# Module-level start time for uptime calculation
_start_time = time.time()


class TargetHealth(BaseModel):
    """Health status for a single MCP target."""
    name: str
    initialized: bool
    tools_count: int
    pending_calls: int
    status: Literal["healthy", "unhealthy"]


class DatabaseHealth(BaseModel):
    """Health status for SQLite database."""
    connected: bool
    status: Literal["healthy", "unhealthy"]


class HealthResponse(BaseModel):
    """Overall health status response."""
    status: Literal["healthy", "degraded", "unhealthy"]
    uptime_seconds: float
    targets: list[TargetHealth]
    database: DatabaseHealth


async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint for k8s probes and monitoring.

    Returns:
        200 - All systems healthy
        503 - One or more systems unhealthy

    Status definitions:
    - "healthy": All targets initialized, database connected
    - "degraded": Some targets failed but database OK
    - "unhealthy": Database unreachable or all targets failed
    """
    state: ProxyState = request.app.state.proxy_state

    # Check database health
    db_health = await _check_database(state)

    # Check per-target health
    target_healths = []
    for target_name, target in state.targets.items():
        target_health = TargetHealth(
            name=target_name,
            initialized=target.initialized,
            tools_count=len(target.tool_schemas),
            pending_calls=len(target.pending_tool_calls),
            status="healthy" if target.initialized else "unhealthy",
        )
        target_healths.append(target_health)

    # Determine overall status
    if not db_health.connected:
        overall_status = "unhealthy"
    elif all(t.status == "healthy" for t in target_healths):
        overall_status = "healthy"
    elif any(t.status == "healthy" for t in target_healths):
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    uptime = time.time() - _start_time

    response = HealthResponse(
        status=overall_status,
        uptime_seconds=uptime,
        targets=target_healths,
        database=db_health,
    )

    status_code = 200 if overall_status != "unhealthy" else 503

    return JSONResponse(response.model_dump(), status_code=status_code)


async def _check_database(state: ProxyState) -> DatabaseHealth:
    """Check database connectivity with a simple query."""
    if state.store is None:
        return DatabaseHealth(connected=False, status="unhealthy")

    try:
        # Execute simple query to verify connection
        async with state.store._db.execute("SELECT 1") as cursor:
            result = await cursor.fetchone()
            connected = result is not None
    except Exception:
        connected = False

    return DatabaseHealth(
        connected=connected,
        status="healthy" if connected else "unhealthy",
    )
