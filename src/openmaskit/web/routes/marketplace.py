"""Marketplace API routes."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from urllib.parse import urlencode
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from openmaskit.oauth import discovery
from openmaskit.oauth.install_flow import prepare_oauth_install
from openmaskit.security import TokenEncryption, validate_server_id
from openmaskit.web.routes._http_config import clean_http_headers

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent.parent / "static"


_ENV_VAR_TYPES = {"text", "secret", "path", "number"}


def _normalize_credential_var(name: str, value, *, target: str) -> dict:
    """Normalize a catalog meta.env / meta.headers entry for the install modal.

    Accepts either the legacy form (string placeholder) or the object form
    ({label, description, type, required}). Unknown/missing fields get safe
    defaults. ``target`` distinguishes env-var vs HTTP-header credentials so
    the modal can post them under separate payload keys.
    """
    if isinstance(value, dict):
        var_type = value.get("type", "text")
        if var_type not in _ENV_VAR_TYPES:
            var_type = "text"
        return {
            "name": name,
            "label": value.get("label") or name,
            "description": value.get("description") or value.get("placeholder") or "",
            "type": var_type,
            "required": bool(value.get("required", True)),
            "target": target,
        }
    # Legacy: bare string was the placeholder.
    return {
        "name": name,
        "label": name,
        "description": str(value) if value else "",
        "type": "text",
        "required": True,
        "target": target,
    }


def _normalize_env_var(name: str, value) -> dict:
    """Backwards-compatible wrapper around _normalize_credential_var for env vars."""
    return _normalize_credential_var(name, value, target="env")


def _normalize_header_var(name: str, value) -> dict:
    """Normalize a catalog meta.headers entry. The key is the literal HTTP
    header name (sent verbatim — no case normalization)."""
    return _normalize_credential_var(name, value, target="header")


def _resolve_mcp_url(
    mcp_host: str, user_params: dict, declared_params: list | None
) -> tuple[str | None, str | None]:
    """Validate user-supplied URL params and append them as a query string.

    Catalog entries that need user-supplied identifiers in the URL (e.g.
    Supabase's `project_ref`) ship a `meta.params` list. The install request
    carries `params: {name: value}`. We require every declared `required`
    param to be present, reject any name not in the declared list (so
    callers can't sneak extra query params onto the upstream URL), and
    URL-encode the values.

    Returns (resolved_url, None) or (None, error_message).
    """
    declared_by_name = {p.get("name"): p for p in (declared_params or []) if p.get("name")}

    for name, decl in declared_by_name.items():
        if decl.get("required", True):
            v = user_params.get(name)
            if not isinstance(v, str) or not v.strip():
                return None, f"param '{name}' is required"

    filled: dict[str, str] = {}
    for name, value in (user_params or {}).items():
        if name not in declared_by_name:
            return None, f"unknown param '{name}'"
        if isinstance(value, str) and value.strip():
            filled[name] = value.strip()

    if not filled:
        return mcp_host, None
    return f"{mcp_host}?{urlencode(filled)}", None


def _oauth_token_path(manager, handle: str) -> Path:
    """Same path FileTokenStorage reads from at runtime: ``{store_dir}/oauth/{handle}.json``."""
    return Path(manager._store_path).expanduser().parent / "oauth" / f"{handle}.json"


def _require_supported(state) -> JSONResponse | None:
    """Return a 426 response if the marketplace backend has declared this
    OpenMaskit version unsupported. Otherwise return None and let the route proceed.
    """
    vs = state.version_status or {}
    if vs.get("update_required"):
        return JSONResponse(
            {
                "error": "OpenMaskit must be updated to install new servers.",
                "latest_version": vs.get("latest_version"),
            },
            status_code=426,
        )
    return None


def _build_config_from_server_info(
    server_info: dict,
    user_env_vars: dict | None = None,
    user_args: dict | None = None
) -> dict:
    """Build upstream config from backend server info.

    Args:
        server_info: Server configuration from backend
        user_env_vars: User-provided environment variable values (for stdio servers)
    """
    transport = server_info.get("transport_type", "http")

    if transport == "http":
        config = {
            "transport": "http",
            "url": server_info["mcp_host"],
            "backend_id": server_info.get("id"),  # Preserve for reauthorize/reconfigure
        }
        # Add OAuth config if the server requires OAuth
        # Token is already stored by oauth_callback, upstream will load it from file
        if server_info.get("requires_oauth"):
            config["oauth"] = {
                "type": "oauth2.1",
                "client_id": "managed-by-backend",  # Placeholder - backend manages this
                "scope": "default",  # Placeholder - backend manages this
            }
        return config
    else:  # stdio (local/docker)
        meta = server_info.get("meta", {})
        # Use user-provided env vars if available, otherwise fall back to keys with
        # empty values. (Catalog meta.env values may be metadata dicts, not real
        # values, so we can't pass them through as-is.)
        if user_env_vars:
            env = user_env_vars
        else:
            raw_env = meta.get("env", {})
            env = {k: (v if isinstance(v, str) else "") for k, v in raw_env.items()}

        # Process user_args into meta.user_args format
        processed_user_args = {}
        if user_args:
            configurable_args = meta.get("configurable_args", [])
            arg_defs = {arg["name"]: arg for arg in configurable_args}

            for arg_name, values in user_args.items():
                if arg_name in arg_defs:
                    arg_def = arg_defs[arg_name]
                    processed_user_args[arg_name] = {
                        "values": values if isinstance(values, list) else [values],
                        "arg_format": arg_def["arg_format"]
                    }

        config = {
            "transport": "stdio",
            "command": meta.get("command", ""),
            "args": meta.get("args", []),
            "env": env,
            "backend_id": server_info.get("id"),  # Preserve for reconfigure
        }

        if processed_user_args:
            config["meta"] = {"user_args": processed_user_args}

        return config


async def marketplace_page(request: Request):
    return FileResponse(STATIC_DIR / "marketplace.html")


async def marketplace_list(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    backend_client = getattr(request.app.state, "backend_client", None)

    if not backend_client:
        return JSONResponse({
            "servers": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0}
        })

    # Extract pagination and search params
    page = int(request.query_params.get("page", 1))
    size = int(request.query_params.get("size", 12))
    query = request.query_params.get("q", "").strip() or None

    # Fetch from backend with pagination and search
    catalog_response = await backend_client.get_catalog(page=page, size=size, query=query)
    backend_catalog = catalog_response["data"]
    meta = catalog_response["meta"]

    installed = await store.get_installed_servers()
    installed_map = {s["id"]: s for s in installed}

    servers = []
    for entry in backend_catalog:
        handle = entry.get("handle")
        if not handle:
            continue

        server_id = handle  # Use handle as local ID
        record = installed_map.get(server_id)
        target = state.get_target(server_id)

        # Normalize meta.env / meta.headers entries — values may be legacy
        # placeholder strings or the object shape ({label, description, type,
        # required}). Header-auth entries (HTTP + meta.headers, no OAuth) feed
        # the same install-modal credential prompt as env vars, with a `target`
        # discriminator so the client posts them under separate payload keys.
        meta_data = entry.get("meta", {}) or {}
        env_vars = [
            _normalize_env_var(k, v) for k, v in meta_data.get("env", {}).items()
        ]
        header_vars = [
            _normalize_header_var(k, v)
            for k, v in (meta_data.get("headers") or {}).items()
        ]

        servers.append({
            "id": server_id,
            "backend_id": entry["id"],  # UUID for backend API
            "handle": handle,
            "name": entry["name"],
            "description": entry.get("description", ""),
            "icon_url": entry.get("icon_url"),
            "category": entry.get("category"),
            "official": entry.get("official", False),
            "tags": entry.get("tags", []),
            "requires_oauth": entry.get("requires_oauth", False),
            "oauth_mode": entry.get("oauth_mode"),  # "byo" | "dcr" | None
            "mcp_host": entry.get("mcp_host"),  # Upstream URL — needed for BYO/DCR install
            "transport_type": entry.get("transport_type", "stdio"),
            "env_vars": env_vars,  # Array of env var names to prompt for
            "header_vars": header_vars,  # Array of HTTP header names to prompt for
            "meta": entry.get("meta", {}),  # Includes configurable_args, available_scopes, setup_guide_url
            "installed": record is not None,
            "active": record["active"] if record else False,
            "connected": target is not None and target.initialized if record and record["active"] else False,
        })

    return JSONResponse({"servers": servers, "meta": meta})


async def marketplace_install(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = getattr(request.app.state, "backend_client", None)
    oauth_states = getattr(request.app.state, "oauth_states", {})

    blocked = _require_supported(state)
    if blocked is not None:
        return blocked

    if not backend_client:
        return JSONResponse({"error": "Backend not available"}, status_code=503)

    body = await request.json()
    server_id = body.get("server_id", "").strip()  # handle
    backend_id = body.get("backend_id", "").strip()  # UUID

    if not server_id or not backend_id:
        return JSONResponse({"error": "server_id and backend_id required"}, status_code=400)

    try:
        server_id = validate_server_id(server_id)
    except ValueError:
        return JSONResponse(
            {"error": "Invalid server_id format"},
            status_code=400
        )

    # Check if server already installed in DB
    existing = await store.get_server(server_id)
    if existing:
        return JSONResponse({"error": "Server already installed"}, status_code=409)

    # Check if there's a config-file target with this name
    if server_id in state.config_target_ids:
        return JSONResponse(
            {"error": f"Server '{server_id}' conflicts with a config-file target"},
            status_code=409,
        )

    # Fetch server details from backend
    server_info = await backend_client.get_server_info(backend_id)
    if not server_info:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    oauth_mode = server_info.get("oauth_mode")

    declared_params = (server_info.get("meta") or {}).get("params") or []
    user_params = body.get("params") or {}

    # BYO: user supplies their own OAuth client credentials. OpenMaskit prepares
    # the OAuth authorize URL and returns it to the FE for a same-tab redirect;
    # the dashboard's /oauth/callback/{handle} route finishes the install.
    if oauth_mode == "byo":
        client_id = (body.get("client_id") or "").strip()
        client_secret = (body.get("client_secret") or "").strip()
        selected_scopes = body.get("selected_scopes") or []

        if not client_id or not client_secret:
            return JSONResponse(
                {"error": "client_id and client_secret are required"},
                status_code=400,
            )

        mcp_host = server_info.get("mcp_host")
        if not mcp_host:
            return JSONResponse(
                {"error": "Catalog entry is missing mcp_host"}, status_code=500
            )

        resolved_url, err = _resolve_mcp_url(mcp_host, user_params, declared_params)
        if err:
            return JSONResponse({"error": err}, status_code=400)

        scope = " ".join(selected_scopes)
        config = {
            "transport": "http",
            "url": resolved_url,
            "oauth": {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
        }
        return await _begin_oauth_install(
            request=request,
            manager=manager,
            oauth_states=oauth_states,
            server_id=server_id,
            server_info=server_info,
            config=config,
            mode="byo",
            resolved_url=resolved_url,
            scope=scope,
            client_id=client_id,
            client_secret=client_secret,
        )

    # DCR: OpenMaskit dynamically registers a client at install time, then prepares
    # the OAuth authorize URL and returns it to the FE for a same-tab redirect;
    # the dashboard's /oauth/callback/{handle} route finishes the install.
    if oauth_mode == "dcr":
        issuer = (body.get("issuer") or "").strip()
        selected_scopes = body.get("selected_scopes") or []
        registration_token = (body.get("registration_token") or "").strip()

        mcp_host = server_info.get("mcp_host")
        if not mcp_host:
            return JSONResponse(
                {"error": "Catalog entry is missing mcp_host"}, status_code=500
            )

        resolved_url, err = _resolve_mcp_url(mcp_host, user_params, declared_params)
        if err:
            return JSONResponse({"error": err}, status_code=400)

        # Catalog entries can omit `oauth.issuer` and rely on install-time
        # discovery (WWW-Authenticate probe → protected-resource metadata →
        # authorization-server metadata). Falls back to host-derived discovery
        # for servers that don't advertise WWW-Authenticate.
        if not issuer:
            discovered = await discovery.discover(resolved_url)
            if not discovered or not discovered.get("issuer"):
                return JSONResponse(
                    {
                        "error": (
                            "OAuth discovery failed; cannot determine authorization server. "
                            "The MCP URL may be unreachable or the server may not advertise OAuth metadata."
                        )
                    },
                    status_code=400,
                )
            issuer = discovered["issuer"]
            discovered_scopes = discovered.get("scopes") or []
            if not selected_scopes and discovered_scopes:
                selected_scopes = [s["scope"] for s in discovered_scopes]
            # WWW-Authenticate required scopes get enforced even if the user
            # picked a custom subset — they can't be deselected without the
            # resource server refusing the token.
            required = [s["scope"] for s in discovered_scopes if s.get("required")]
            if required:
                selected_scopes = list(
                    dict.fromkeys(list(selected_scopes) + required)
                )

        oauth_cfg: dict = {"issuer": issuer, "scopes": selected_scopes}
        if registration_token:
            oauth_cfg["registration_token"] = registration_token

        config = {"transport": "http", "url": resolved_url, "oauth": oauth_cfg}
        scope = " ".join(selected_scopes)
        return await _begin_oauth_install(
            request=request,
            manager=manager,
            oauth_states=oauth_states,
            server_id=server_id,
            server_info=server_info,
            config=config,
            mode="dcr",
            resolved_url=resolved_url,
            scope=scope,
            issuer=issuer,
            registration_token=registration_token or None,
        )

    # Hosted-broker OAuth: redirect through auth.maskitmcp.com.
    if server_info.get("requires_oauth"):
        csrf_state = str(uuid4())
        oauth_states[csrf_state] = {
            "mode": "broker",
            "server_id": backend_id,
            "handle": server_id,
            "timestamp": time.time(),
        }

        base_url = f"{request.url.scheme}://{request.url.netloc}"
        redirect_uri = f"{base_url}/oauth/callback/{server_id}"
        oauth_url = backend_client.get_oauth_authorize_url(
            server_id=backend_id, state=csrf_state, redirect_uri=redirect_uri
        )

        logger.info(f"Initiating OAuth flow for {server_id}: {oauth_url}")
        return JSONResponse({"ok": True, "requires_oauth": True, "oauth_url": oauth_url})

    # HTTP + static-header auth (Datadog-style): no OAuth, but the catalog
    # entry declares header-name credentials in meta.headers.
    transport_type = server_info.get("transport_type", "stdio")
    declared_headers = (server_info.get("meta") or {}).get("headers") or {}
    if transport_type == "http" and declared_headers:
        mcp_host = server_info.get("mcp_host")
        if not mcp_host:
            return JSONResponse(
                {"error": "Catalog entry is missing mcp_host"}, status_code=500
            )
        resolved_url, err = _resolve_mcp_url(mcp_host, user_params, declared_params)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        user_headers, header_err = clean_http_headers(body.get("headers"))
        if header_err:
            return JSONResponse({"error": header_err}, status_code=400)
        # Required-header check: every declared `required: true` entry must
        # have a non-empty value in the request.
        for name, decl in declared_headers.items():
            required = True if not isinstance(decl, dict) else bool(
                decl.get("required", True)
            )
            if required and name.strip() not in user_headers:
                return JSONResponse(
                    {"error": f"header '{name}' is required"}, status_code=400
                )
        config = {
            "transport": "http",
            "url": resolved_url,
            "headers": user_headers,
            "backend_id": server_info.get("id"),
        }
        return await _install_and_connect(store, manager, server_id, server_info, config)

    # Non-OAuth server: connect immediately
    # Get user-provided env vars and args from request
    user_env_vars = body.get("env_vars", {})
    user_args = body.get("user_args", {})
    config = _build_config_from_server_info(server_info, user_env_vars, user_args)
    return await _install_and_connect(store, manager, server_id, server_info, config)


async def _begin_oauth_install(
    *,
    request: Request,
    manager,
    oauth_states: dict,
    server_id: str,
    server_info: dict,
    config: dict,
    mode: str,
    resolved_url: str,
    scope: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    issuer: str | None = None,
    registration_token: str | None = None,
    reauthorize: bool = False,
) -> JSONResponse:
    """Prepare a BYO/DCR install or reauthorize and return the authorize URL.

    Stashes everything the callback needs (token endpoint, client credentials,
    PKCE verifier, target config) in the process-wide ``oauth_states`` map
    keyed by the OAuth ``state`` parameter. The FE redirects the dashboard tab
    to ``oauth_url``; the AS bounces back to ``/oauth/callback/{handle}`` where
    ``oauth_callback`` finishes the flow.
    """
    if manager is None:
        return JSONResponse(
            {"error": "Target manager not available"}, status_code=503
        )
    store_path = _oauth_token_path(manager, server_id)
    base_url = f"{request.url.scheme}://{request.url.netloc}"

    try:
        prep = await prepare_oauth_install(
            resolved_url=resolved_url,
            mode=mode,  # type: ignore[arg-type]
            store_path=store_path,
            base_url=base_url,
            handle=server_id,
            scope=scope,
            client_id=client_id,
            client_secret=client_secret,
            issuer=issuer,
            registration_token=registration_token,
        )
    except RuntimeError as exc:
        logger.exception(f"OAuth install prep failed for {server_id}")
        return JSONResponse({"error": str(exc)}, status_code=400)

    oauth_states[prep.state] = {
        "mode": mode,
        "handle": server_id,
        "timestamp": time.time(),
        "token_endpoint": prep.token_endpoint,
        "client_id": prep.client_id,
        "client_secret": prep.client_secret,
        "auth_method": prep.auth_method,
        "code_verifier": prep.code_verifier,
        "redirect_uri": prep.redirect_uri,
        "scope": prep.scope,
        "resource": prep.resource,
        "server_info": server_info,
        "icon_url": server_info.get("icon_url"),
        "config": config,
        "reauthorize": reauthorize,
    }
    logger.info(
        f"Prepared {mode} OAuth flow for {server_id} "
        f"(reauthorize={reauthorize}); returning oauth_url to FE"
    )
    return JSONResponse({"ok": True, "oauth_url": prep.oauth_url})


async def _install_and_connect(store, manager, server_id, server_info, config) -> JSONResponse:
    """Persist a marketplace server and attempt to connect it. On connect failure,
    the server is left installed but deactivated so the user can retry from the UI.
    """
    icon_url = server_info.get("icon_url")
    await store.install_server(server_id, server_info["name"], config, icon_url)

    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(server_id, config)
            connected = True
            logger.info(f"Successfully connected marketplace server: {server_id}")
        except Exception as exc:
            logger.exception(f"Failed to connect {server_id}")
            if hasattr(exc, "exceptions") and exc.exceptions:
                error_msg = str(exc.exceptions[0])
            else:
                error_msg = str(exc)
            await store.deactivate_server(server_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result, status_code=201)


async def marketplace_reauthorize(request: Request):
    """Trigger a fresh OAuth flow for an installed server.

    All three modes (broker / BYO / DCR) now return a fresh ``oauth_url`` for
    the dashboard to navigate to in-tab. The callback handler at
    ``/oauth/callback/{handle}`` exchanges the code, writes new tokens, and
    reconnects the target.
    """
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = getattr(request.app.state, "backend_client", None)
    oauth_states = getattr(request.app.state, "oauth_states", {})

    target_id = request.path_params.get("target_id")
    if not target_id:
        return JSONResponse({"error": "target_id required"}, status_code=400)

    existing = await store.get_server(target_id)
    if not existing:
        return JSONResponse({"error": "Server not installed"}, status_code=404)

    config = existing["config"]
    oauth_cfg = config.get("oauth") or {}
    if not oauth_cfg:
        return JSONResponse(
            {"error": "Server does not use OAuth"}, status_code=400
        )

    # Hosted-broker installs are tagged with the "managed-by-backend" placeholder.
    is_hosted_broker = oauth_cfg.get("client_id") == "managed-by-backend"

    if is_hosted_broker:
        if not backend_client:
            return JSONResponse({"error": "Backend not available"}, status_code=503)
        backend_id = config.get("backend_id")
        if not backend_id:
            return JSONResponse(
                {"error": "Server missing backend_id; cannot reauthorize"},
                status_code=500,
            )

        csrf_state = str(uuid4())
        oauth_states[csrf_state] = {
            "mode": "broker",
            "server_id": backend_id,
            "handle": target_id,
            "timestamp": time.time(),
        }
        base_url = f"{request.url.scheme}://{request.url.netloc}"
        redirect_uri = f"{base_url}/oauth/callback/{target_id}"
        oauth_url = backend_client.get_oauth_authorize_url(
            server_id=backend_id, state=csrf_state, redirect_uri=redirect_uri
        )
        return JSONResponse({"ok": True, "oauth_url": oauth_url})

    # BYO / DCR: build a fresh authorize URL and return it for in-tab redirect.
    if not manager:
        return JSONResponse({"error": "Target manager not available"}, status_code=503)

    resolved_url = config.get("url")
    if not resolved_url:
        return JSONResponse(
            {"error": "Server config missing url; cannot reauthorize"},
            status_code=500,
        )

    # Drop only the tokens — keep client_info on disk so BYO doesn't re-prompt
    # and DCR doesn't re-register against the AS.
    _clear_oauth_tokens(_oauth_token_path(manager, target_id))

    if oauth_cfg.get("issuer"):
        mode = "dcr"
        scope_str = " ".join(oauth_cfg.get("scopes") or [])
        return await _begin_oauth_install(
            request=request,
            manager=manager,
            oauth_states=oauth_states,
            server_id=target_id,
            server_info={},
            config=config,
            mode=mode,
            resolved_url=resolved_url,
            scope=scope_str,
            issuer=oauth_cfg["issuer"],
            registration_token=oauth_cfg.get("registration_token"),
            reauthorize=True,
        )

    # BYO
    return await _begin_oauth_install(
        request=request,
        manager=manager,
        oauth_states=oauth_states,
        server_id=target_id,
        server_info={},
        config=config,
        mode="byo",
        resolved_url=resolved_url,
        scope=oauth_cfg.get("scope") or "",
        client_id=oauth_cfg.get("client_id"),
        client_secret=oauth_cfg.get("client_secret"),
        reauthorize=True,
    )


def _clear_oauth_tokens(token_path: Path) -> None:
    """Drop the tokens key from the encrypted token file, preserving client_info.

    If the file is missing or unreadable, ensure it doesn't exist so the next OAuth
    flow re-seeds it from scratch.
    """
    if not token_path.exists():
        return

    encryption = TokenEncryption()
    try:
        ciphertext = token_path.read_text()
        plaintext = encryption.decrypt(ciphertext)
        data = json.loads(plaintext)
    except Exception as e:
        logger.warning(f"Could not parse token file {token_path}: {e}; deleting.")
        token_path.unlink(missing_ok=True)
        return

    data.pop("tokens", None)
    if not data:
        token_path.unlink(missing_ok=True)
        return

    new_plaintext = json.dumps(data, indent=2, default=str)
    token_path.write_text(encryption.encrypt(new_plaintext))
    token_path.chmod(0o600)


async def marketplace_deactivate(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    body = await request.json()
    server_id = body.get("server_id", "").strip()

    if not server_id:
        return JSONResponse({"error": "server_id is required"}, status_code=400)

    existing = await store.get_server(server_id)
    if not existing:
        return JSONResponse({"error": "Server not installed"}, status_code=404)

    if manager:
        try:
            await manager.remove_target(server_id)
        except Exception as exc:
            logger.warning("Error removing target %s: %s", server_id, exc)

    await store.deactivate_server(server_id)
    return JSONResponse({"ok": True})


async def marketplace_activate(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    blocked = _require_supported(state)
    if blocked is not None:
        return blocked

    body = await request.json()
    server_id = body.get("server_id", "").strip()

    if not server_id:
        return JSONResponse({"error": "server_id is required"}, status_code=400)

    existing = await store.get_server(server_id)
    if not existing:
        return JSONResponse({"error": "Server not installed"}, status_code=404)

    if server_id in state.targets:
        return JSONResponse({"error": "Server is already active"}, status_code=409)

    config = existing["config"]
    connected = False
    error_msg = None

    if manager:
        try:
            await manager.add_target(server_id, config)
            connected = True
        except Exception as exc:
            logger.exception("Failed to reconnect marketplace server %s", server_id)
            # Unwrap ExceptionGroup to get the real error
            if hasattr(exc, 'exceptions') and exc.exceptions:
                error_msg = str(exc.exceptions[0])
            else:
                error_msg = str(exc)

    if connected:
        await store.activate_server(server_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result)


async def reconfigure_target(request: Request):
    """Reconfigure an installed server's user_args and reconnect."""
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = getattr(request.app.state, "backend_client", None)

    # Get target_id from path params
    target_id = request.path_params.get("target_id")
    if not target_id:
        return JSONResponse({"error": "target_id required"}, status_code=400)

    body = await request.json()
    user_args: dict = body.get("user_args", {})

    # Get current server config
    server = await store.get_server(target_id)
    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    config = server["config"]

    # Get configurable_args schema (from backend if marketplace server)
    configurable_args = []
    if backend_client and backend_client.enabled:
        try:
            backend_id = config.get("backend_id")
            if backend_id:
                server_info = await backend_client.get_server_info(backend_id)
                if server_info:
                    configurable_args = server_info.get("meta", {}).get("configurable_args", [])
        except Exception as e:
            logger.warning(f"Failed to fetch configurable_args for {target_id}: {e}")

    # Process user_args into meta.user_args format
    processed_user_args = {}
    if user_args and configurable_args:
        arg_defs = {arg["name"]: arg for arg in configurable_args}

        for arg_name, values in user_args.items():
            if arg_name in arg_defs:
                arg_def = arg_defs[arg_name]
                processed_user_args[arg_name] = {
                    "values": values if isinstance(values, list) else [values],
                    "arg_format": arg_def["arg_format"]
                }

    # Update config
    if "meta" not in config:
        config["meta"] = {}
    config["meta"]["user_args"] = processed_user_args

    # Save to DB
    await store.update_server_config(target_id, config)

    # Reconnect: disconnect then add_target with new config
    try:
        if manager:
            await manager.remove_target(target_id)
            await manager.add_target(target_id, config)
        logger.info(f"Reconfigured and reconnected {target_id}")
        return JSONResponse({"success": True})
    except Exception as e:
        logger.error(f"Failed to reconnect {target_id}: {e}")
        # Unwrap ExceptionGroup
        if hasattr(e, 'exceptions') and e.exceptions:
            error_msg = str(e.exceptions[0])
        else:
            error_msg = str(e)
        return JSONResponse({"error": error_msg}, status_code=500)
