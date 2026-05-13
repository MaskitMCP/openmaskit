# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Maskit

Maskit is an MCP (Model Context Protocol) server proxy that sits between an AI host (e.g., Claude Code) and a real MCP server. It intercepts tool call responses to mask sensitive field values (replacing `prod-db.internal.net` with `host_1`) and unmasks them when the agent sends those aliases back in tool call arguments.

## Commands

```bash
uv sync                          # Install dependencies
uv run pytest tests/ -v          # Run all tests
uv run pytest tests/test_engine.py::TestMaskingEngine::test_mask_structured_content -v  # Single test
uv run maskit                    # Run with ./maskit.yaml
uv run maskit path/to/config.yaml  # Run with custom config
```

## Naming

The UI says "Servers" but the codebase uses "target" everywhere (classes, DB columns, API routes, variables). They mean the same thing — an upstream MCP server that Maskit proxies to. "Server" is the user-facing term; "target" is the internal term. Do not rename internal code.

## Architecture

The system has four concurrent components running in one asyncio event loop (via anyio task groups):

1. **Proxy Core** (`__main__.py` + `proxy/core.py`) — Bidirectional JSON-RPC relay between downstream clients and upstream MCP server. Operates at the raw `JSONRPCMessage` level for full protocol transparency — all non-tool messages pass through unmodified. Bootstraps the upstream session (initialize + tools/list) at startup.

2. **MCP HTTP Endpoint** (`proxy/http_downstream.py`, Starlette on port 9474) — HTTP MCP endpoint that AI agents connect to. Implements the MCP streamable HTTP transport (POST /mcp). Uses `ResponseDispatcher` to correlate requests with responses through the proxy relay.

3. **Masking Engine** (`masking/engine.py`) — Synchronous mask/unmask using an in-memory cache. Aliases are created in-memory for speed (`_alias_cache`, `_reverse_cache`) and flushed to SQLite periodically by `_flush_loop`. The engine handles both `structuredContent` dicts (path-based masking) and `TextContent` blocks (JSON/Python-repr-parse-then-mask, fallback to string replacement). Supports two mapper types: `regex_replace` (regex pattern matching on text) and `json_field_mask` (dot-notation path targeting specific fields in parsed JSON/repr).

4. **Web UI** (`web/app.py`, Starlette on port 9473) — Dashboard for viewing tool schemas, managing masking rules, trying out tools, and observing live traffic over WebSocket.

### Key data flow

```
AI Agent HTTP (:9474/mcp) ─┐
                            ├──► ds_read stream
AI Host stdin ─────────────┘         ↓
                         _intercept_request (unmask aliases in arguments)
                                     ↓
                              upstream MCP server
                                     ↓
                         _intercept_response (mask values, cache tool schemas)
                                     ↓
                         ResponseDispatcher (routes to HTTP waiters)
                                     ↓ (if no waiter)
                              ds_write stream → _stdout_writer → AI Host stdout
```

### Important: stdout is sacred

The MCP stdio protocol uses stdout exclusively. All logging goes to stderr. The Web UI must never write to stdout.

### ResponseDispatcher pattern

HTTP clients (MCP endpoint and web UI "Try it out") register a waiter by request ID before injecting a message into the proxy relay. When the response arrives from upstream, `_relay_upstream_to_downstream` checks the dispatcher first — if a waiter exists, it routes the response directly to the waiter instead of sending it to stdout.

### Masking engine's dual-layer caching

`MaskingEngine.mask_response()` is synchronous (called from the proxy relay hot path). It writes new aliases to `_pending_writes` which are batch-flushed to SQLite every second by `_flush_loop` in `__main__.py`. This avoids blocking the relay on DB I/O.

### Hidden tools

Tools can be hidden per-server via the Web UI. Hidden tools are stored in the `hidden_tools` SQLite table and loaded into `TargetState.hidden_tools` at startup. When an agent calls a hidden tool, the proxy returns a `METHOD_NOT_FOUND` error without forwarding to upstream.

### Request interception pipeline

In `_intercept_request()`, tool calls pass through these stages in order:
1. **Hidden tool check** — blocks with `METHOD_NOT_FOUND` error
2. **Unmask arguments** — replaces aliases with real values
3. **Guardrail check** — validates unmasked args against patterns, blocks with `-32602` error if violated
4. **Injection application** — injects/overrides argument values before forwarding

### Argument guardrails

Block tool calls whose arguments match dangerous patterns. Stored in `guardrails` table, loaded into `MaskingEngine._guardrails`. Support three match types: `contains`, `equals`, `regex`. When `argument_name="*"`, scans all string values recursively.

### Argument injections

Silently inject or override argument values before forwarding. Stored in `injections` table, loaded into `MaskingEngine._injections`. Three modes: `set` (always override), `default` (only if absent), `append` (append to string/list). Values are JSON-encoded strings.

### Field stripping

Rules with `action="strip"` remove fields entirely from responses (no alias created, field is gone). Only applies to structured data (parsed JSON/repr); plain text blocks skip strip rules.

### Text parsing (`masking/parsing.py`)

The `try_parse_structured` utility attempts JSON first, then falls back to `ast.literal_eval` for Python repr strings (common in some MCP tool responses). Results are serialized back in their original format after masking.

### Persistence

SQLite database (default `~/.maskit/store.db`) with tables:
- `mappings` — alias ↔ real_value (persists across restarts so the same real value always gets the same alias)
- `rules` — masking rules created via Web UI (merged with config-file rules at startup), supports `action` column (`mask` or `strip`)
- `response_mappers` — output mapper configs (regex or json_field_mask) with optional `config` JSON column
- `hidden_tools` — tools hidden per server (blocked from agent access)
- `guardrails` — argument validation rules that block tool calls matching dangerous patterns
- `injections` — argument injection rules that inject/override values before forwarding
- `mcp_servers` — marketplace and custom servers (id, name, config JSON, active flag). Used for both marketplace installs and custom targets added via the UI

### Marketplace

The marketplace allows users to install pre-configured MCP servers from a catalog (`marketplace.json` at repo root). Installed servers are persisted in the `mcp_servers` SQLite table and connected at runtime via `TargetManager`.

- Catalog entries define transport, command/URL, required env vars, and optional OAuth vars
- On install, the user provides credentials via a modal; the config is saved and the server is hot-connected
- Servers can be deactivated (disconnected but config retained) and reactivated without re-entering credentials
- Active marketplace servers are automatically reconnected on startup (`__main__.py` loads them from DB)

### Custom targets (runtime)

Users can add arbitrary MCP servers via the dashboard (Servers page → "Add Server"). These are also stored in the `mcp_servers` SQLite table and managed by `TargetManager`. Same hot-add/remove lifecycle as marketplace servers.

### TargetManager (`proxy/manager.py`)

Handles hot-adding and removing MCP server targets at runtime. Holds references to the shared task group and exit stack so it can spawn proxy loops and connect upstream without restarting. Called by both marketplace and custom target API routes.

### OAuth handler (`oauth/handler.py`)

Shared OAuth 2.1 callback server running on port 3118. Used by HTTP upstream targets that require OAuth (e.g., Slack). The callback server is started once in `__main__.py` and shared across all targets. OAuth tokens are stored per-server at `{store_dir}/oauth/{server_id}.json`.

## Configuration

`maskit.yaml` at project root. Upstream supports `stdio` transport (spawns child process) and `http` transport (connects to remote MCP server with optional OAuth 2.1). If no config file exists, Maskit starts with no pre-configured targets (marketplace/custom targets can still be added via UI).

## Web UI

### Pages

- `/` — Servers page: lists all connected targets (config, marketplace, custom), add/remove custom servers
- `/marketplace` — Browse and install servers from the catalog
- `/targets/{name}/tools` — Tool list for a specific server, connect agent button
- `/targets/{name}/tools/{tool}` — Tool detail: schema, try it out, masking rules, mappers, guardrails, injections

### API routes

All target-scoped routes: `/api/targets/{target_name}/...`

- `GET /api/targets/{target_name}/tools` — cached tool schemas
- `POST /api/targets/{target_name}/tools/call` — invoke a tool through the proxy (used by "Try it out")
- `GET/POST/PUT/DELETE /api/targets/{target_name}/rules` — masking rule CRUD (supports `action: "mask"|"strip"`)
- `GET/POST/PUT/DELETE /api/targets/{target_name}/mappers` — response mapper CRUD
- `GET/POST/PUT/DELETE /api/targets/{target_name}/guardrails` — argument guardrail CRUD
- `GET/POST/PUT/DELETE /api/targets/{target_name}/injections` — argument injection CRUD
- `GET /api/targets/{target_name}/mappings` — current alias mappings
- `GET/POST /api/targets/{target_name}/hidden_tools` — hide/unhide tools from the agent
- `WS /ws/traffic` — live traffic stream

Marketplace routes:

- `GET /api/marketplace` — catalog with install/active status
- `POST /api/marketplace/install` — install a server from catalog
- `POST /api/marketplace/activate` — reactivate a previously installed server
- `POST /api/marketplace/deactivate` — disconnect and deactivate

Custom target routes:

- `GET /api/custom-targets` — list custom targets
- `POST /api/custom-targets` — add a new custom target
- `DELETE /api/custom-targets/{id}` — remove a custom target
