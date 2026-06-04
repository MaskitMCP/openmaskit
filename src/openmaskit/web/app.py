"""Web UI application factory."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from openmaskit.web.csrf import CsrfMiddleware, generate_csrf_token
from openmaskit.web.origin import OriginMiddleware, default_localhost_origins

if TYPE_CHECKING:
    from openmaskit.proxy.core import ProxyState

STATIC_DIR = Path(__file__).parent / "static"

_ORIGIN_REQUIRED_METHODS = ("POST", "PUT", "DELETE", "PATCH")


def create_app(
    state: ProxyState,
    allowed_origins: Iterable[str] | None = None,
    csrf_token: str | None = None,
) -> Starlette:
    from openmaskit.web.routes.custom_targets import (
        custom_target_activate,
        custom_target_create,
        custom_target_deactivate,
        custom_target_delete,
        custom_target_get,
        custom_target_update,
    )
    from openmaskit.web.routes.hidden_tools import hidden_tools_list, hidden_tools_toggle
    from openmaskit.web.routes.mappers import (
        mappers_create,
        mappers_delete,
        mappers_list,
        mappers_preview,
        mappers_preview_json,
        mappers_reorder,
        mappers_update,
        parse_text,
    )
    from openmaskit.web.routes.marketplace import (
        marketplace_activate,
        marketplace_deactivate,
        marketplace_install,
        marketplace_list,
        marketplace_page,
        marketplace_reauthorize,
        reconfigure_target,
    )
    from openmaskit.web.routes.oauth_callback import oauth_callback
    from openmaskit.web.routes.oauth import discover_oauth_metadata
    from openmaskit.web.routes.pages import (
        api_config,
        api_csrf,
        api_targets,
        api_tools,
        api_tools_call,
        targets_page,
        tool_detail_page,
        tools_page,
    )
    from openmaskit.web.routes.guardrails import (
        guardrails_create,
        guardrails_delete,
        guardrails_list,
        guardrails_update,
    )
    from openmaskit.web.routes.injections import (
        injections_create,
        injections_delete,
        injections_list,
        injections_update,
    )
    from openmaskit.web.routes.rules import rules_create, rules_delete, rules_list, rules_update
    from openmaskit.web.routes.traffic import api_mappings, api_traffic
    from openmaskit.web.health import health_check

    routes = [
        Route("/", targets_page),
        Route("/marketplace", marketplace_page),
        Route("/health", health_check, methods=["GET"]),
        Route("/api/csrf", api_csrf),
        Route("/api/marketplace", marketplace_list),
        Route("/api/marketplace/install", marketplace_install, methods=["POST"]),
        Route("/api/marketplace/deactivate", marketplace_deactivate, methods=["POST"]),
        Route("/api/marketplace/activate", marketplace_activate, methods=["POST"]),
        Route("/api/marketplace/{target_id}/reauthorize", marketplace_reauthorize, methods=["POST"]),
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
        Route("/api/targets/{target_name}/traffic", api_traffic),
        Route("/targets/{target_name}/tools/{tool_name:path}", tool_detail_page),
        Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
    ]

    if allowed_origins is None:
        web_port = getattr(state, "web_port", 9473)
        allowed_origins = default_localhost_origins(web_port)

    if csrf_token is None:
        csrf_token = generate_csrf_token()

    middleware = [
        Middleware(
            OriginMiddleware,
            allowed_origins=list(allowed_origins),
            require_origin_methods=_ORIGIN_REQUIRED_METHODS,
        ),
        Middleware(CsrfMiddleware, token=csrf_token),
    ]

    app = Starlette(routes=routes, middleware=middleware)
    app.state.proxy_state = state
    app.state.csrf_token = csrf_token
    return app
