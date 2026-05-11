"""Web UI application factory."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

if TYPE_CHECKING:
    from maskit.proxy.core import ProxyState

STATIC_DIR = Path(__file__).parent / "static"


def create_app(state: ProxyState) -> Starlette:
    from maskit.web.routes.mappers import (
        mappers_create,
        mappers_delete,
        mappers_list,
        mappers_preview,
        mappers_reorder,
    )
    from maskit.web.routes.pages import (
        api_targets,
        api_tools,
        api_tools_call,
        targets_page,
        tool_detail_page,
        tools_page,
    )
    from maskit.web.routes.rules import rules_create, rules_delete, rules_list
    from maskit.web.routes.traffic import TrafficWebSocket, api_mappings

    routes = [
        Route("/", targets_page),
        Route("/targets/{target_name}/tools", tools_page),
        Route("/api/targets", api_targets),
        Route("/api/targets/{target_name}/tools", api_tools),
        Route("/api/targets/{target_name}/tools/call", api_tools_call, methods=["POST"]),
        Route("/api/targets/{target_name}/rules", rules_list, methods=["GET"]),
        Route("/api/targets/{target_name}/rules/create", rules_create, methods=["POST"]),
        Route("/api/targets/{target_name}/rules/{rule_id:int}/delete", rules_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/mappers", mappers_list, methods=["GET"]),
        Route("/api/targets/{target_name}/mappers/create", mappers_create, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/{mapper_id:int}/delete", mappers_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/mappers/preview", mappers_preview, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/reorder", mappers_reorder, methods=["POST"]),
        Route("/api/targets/{target_name}/mappings", api_mappings),
        WebSocketRoute("/ws/targets/{target_name}/traffic", TrafficWebSocket),
        Route("/targets/{target_name}/tools/{tool_name:path}", tool_detail_page),
        Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
    ]

    app = Starlette(routes=routes)
    app.state.proxy_state = state
    return app
