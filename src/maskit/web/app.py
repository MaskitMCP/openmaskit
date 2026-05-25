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
    from maskit.web.routes.custom_targets import (
        custom_target_activate,
        custom_target_create,
        custom_target_deactivate,
        custom_target_delete,
        custom_target_get,
        custom_target_update,
    )
    from maskit.web.routes.hidden_tools import hidden_tools_list, hidden_tools_toggle
    from maskit.web.routes.mappers import (
        mappers_create,
        mappers_delete,
        mappers_list,
        mappers_preview,
        mappers_preview_json,
        mappers_reorder,
        mappers_update,
        parse_text,
    )
    from maskit.web.routes.marketplace import (
        marketplace_activate,
        marketplace_deactivate,
        marketplace_install,
        marketplace_list,
        marketplace_page,
        reconfigure_target,
    )
    from maskit.web.routes.oauth_callback import oauth_callback
    from maskit.web.routes.oauth import discover_oauth_metadata
    from maskit.web.routes.pages import (
        api_config,
        api_targets,
        api_tools,
        api_tools_call,
        targets_page,
        tool_detail_page,
        tools_page,
    )
    from maskit.web.routes.guardrails import (
        guardrails_create,
        guardrails_delete,
        guardrails_list,
        guardrails_update,
    )
    from maskit.web.routes.injections import (
        injections_create,
        injections_delete,
        injections_list,
        injections_update,
    )
    from maskit.web.routes.rules import rules_create, rules_delete, rules_list, rules_update
    from maskit.web.routes.traffic import TrafficWebSocket, api_mappings
    from maskit.web.health import health_check

    routes = [
        Route("/", targets_page),
        Route("/marketplace", marketplace_page),
        Route("/health", health_check, methods=["GET"]),
        Route("/api/marketplace", marketplace_list),
        Route("/api/marketplace/install", marketplace_install, methods=["POST"]),
        Route("/api/marketplace/deactivate", marketplace_deactivate, methods=["POST"]),
        Route("/api/marketplace/activate", marketplace_activate, methods=["POST"]),
        Route("/api/targets/{target_id}/reconfigure", reconfigure_target, methods=["POST"]),
        Route("/oauth/callback/{handle}", oauth_callback, methods=["GET"]),
        Route("/api/oauth/discover", discover_oauth_metadata, methods=["POST"]),
        Route("/targets/{target_name}/tools", tools_page),
        Route("/api/config", api_config),
        Route("/api/targets/custom", custom_target_create, methods=["POST"]),
        Route("/api/targets/custom/{target_id}", custom_target_get, methods=["GET"]),
        Route("/api/targets/custom/{target_id}/update", custom_target_update, methods=["POST"]),
        Route("/api/targets/custom/{target_id}/delete", custom_target_delete, methods=["POST"]),
        Route("/api/targets/custom/{target_id}/activate", custom_target_activate, methods=["POST"]),
        Route("/api/targets/custom/{target_id}/deactivate", custom_target_deactivate, methods=["POST"]),
        Route("/api/targets", api_targets),
        Route("/api/targets/{target_name}/tools", api_tools),
        Route("/api/targets/{target_name}/tools/call", api_tools_call, methods=["POST"]),
        Route("/api/targets/{target_name}/rules", rules_list, methods=["GET"]),
        Route("/api/targets/{target_name}/rules/create", rules_create, methods=["POST"]),
        Route("/api/targets/{target_name}/rules/{rule_id:int}/update", rules_update, methods=["POST"]),
        Route("/api/targets/{target_name}/rules/{rule_id:int}/delete", rules_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/mappers", mappers_list, methods=["GET"]),
        Route("/api/targets/{target_name}/mappers/create", mappers_create, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/{mapper_id:int}/update", mappers_update, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/{mapper_id:int}/delete", mappers_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/mappers/preview", mappers_preview, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/preview_json", mappers_preview_json, methods=["POST"]),
        Route("/api/targets/{target_name}/mappers/reorder", mappers_reorder, methods=["POST"]),
        Route("/api/targets/{target_name}/parse_text", parse_text, methods=["POST"]),
        Route("/api/targets/{target_name}/guardrails", guardrails_list, methods=["GET"]),
        Route("/api/targets/{target_name}/guardrails/create", guardrails_create, methods=["POST"]),
        Route("/api/targets/{target_name}/guardrails/{guardrail_id:int}/update", guardrails_update, methods=["POST"]),
        Route("/api/targets/{target_name}/guardrails/{guardrail_id:int}/delete", guardrails_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/injections", injections_list, methods=["GET"]),
        Route("/api/targets/{target_name}/injections/create", injections_create, methods=["POST"]),
        Route("/api/targets/{target_name}/injections/{injection_id:int}/update", injections_update, methods=["POST"]),
        Route("/api/targets/{target_name}/injections/{injection_id:int}/delete", injections_delete, methods=["POST", "DELETE"]),
        Route("/api/targets/{target_name}/hidden_tools", hidden_tools_list, methods=["GET"]),
        Route("/api/targets/{target_name}/hidden_tools/toggle", hidden_tools_toggle, methods=["POST"]),
        Route("/api/targets/{target_name}/mappings", api_mappings),
        WebSocketRoute("/ws/targets/{target_name}/traffic", TrafficWebSocket),
        Route("/targets/{target_name}/tools/{tool_name:path}", tool_detail_page),
        Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
    ]

    app = Starlette(routes=routes)
    app.state.proxy_state = state
    return app
