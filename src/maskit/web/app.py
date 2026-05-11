"""Web UI application factory."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

if TYPE_CHECKING:
    from anyio.streams.memory import MemoryObjectSendStream

    from mcp.shared.message import SessionMessage

    from maskit.proxy.core import ProxyState

STATIC_DIR = Path(__file__).parent / "static"


def create_app(state: ProxyState, ds_read_send: MemoryObjectSendStream[SessionMessage | Exception]) -> Starlette:
    from maskit.web.routes.mappers import (
        mappers_create,
        mappers_delete,
        mappers_list,
        mappers_preview,
        mappers_reorder,
    )
    from maskit.web.routes.pages import api_tools, api_tools_call, index_page, tool_detail_page, tools_page
    from maskit.web.routes.rules import rules_create, rules_delete, rules_list
    from maskit.web.routes.traffic import TrafficWebSocket, api_mappings

    routes = [
        Route("/", index_page),
        Route("/tools", tools_page),
        Route("/api/tools", api_tools),
        Route("/api/tools/call", api_tools_call, methods=["POST"]),
        Route("/api/rules", rules_list, methods=["GET"]),
        Route("/api/rules/create", rules_create, methods=["POST"]),
        Route("/api/rules/{rule_id:int}/delete", rules_delete, methods=["POST", "DELETE"]),
        Route("/api/mappers", mappers_list, methods=["GET"]),
        Route("/api/mappers/create", mappers_create, methods=["POST"]),
        Route("/api/mappers/{mapper_id:int}/delete", mappers_delete, methods=["POST", "DELETE"]),
        Route("/api/mappers/preview", mappers_preview, methods=["POST"]),
        Route("/api/mappers/reorder", mappers_reorder, methods=["POST"]),
        Route("/api/mappings", api_mappings),
        WebSocketRoute("/ws/traffic", TrafficWebSocket),
        Route("/tools/{tool_name:path}", tool_detail_page),
        Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
    ]

    app = Starlette(routes=routes)
    app.state.proxy_state = state
    app.state.ds_read_send = ds_read_send
    return app
