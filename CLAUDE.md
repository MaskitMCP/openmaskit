# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Maskit

Maskit is an MCP (Model Context Protocol) server proxy that sits between an AI host (e.g., Claude Code) and a real MCP server. It intercepts tool call responses to mask sensitive field values (replacing `prod-db.internal.net` with `host_1`) and unmasks them when the agent sends those aliases back in tool call arguments.

## Deployment model (important for security reasoning)

Maskit runs **locally on the user's own machine** — like a CLI dev tool (Docker Desktop, Jupyter, a local DB client). It is **not a hosted service**, the Python backend is **not deployed anywhere**, and the FE↔Python channel is a localhost link on the same machine. So:

- **Localhost-only auth on the Web UI / API / MCP endpoint is not required.** The user already owns the machine.
- **Running arbitrary subprocesses (stdio targets, `docker run ...` from the marketplace) is not RCE in any meaningful sense.** Maskit is a UI for commands the user would otherwise type into their own terminal — it confers no privilege the user doesn't already have.
- **Multi-user shared-machine threats (other local users reading token files, etc.) are out of scope** unless explicitly raised.

The threats that **do** still matter, even for a local tool:

- **Browser-based cross-origin attacks against localhost.** A malicious webpage the user visits can `fetch()`/`WebSocket` against `127.0.0.1:9473`/`9474`/`3131` and exfiltrate secrets. This is the canonical "localhost service" attack class (cf. the Docker daemon, ethdev wallets, etc.). CSRF tokens, `Origin` header checks on POST and WS, and not echoing the alias map / unmasked previews to API callers are all still required.
- **OAuth callback integrity** — the OAuth flow physically goes through the browser, so `state` validation and code-injection defenses still apply.
- **Malicious upstream MCP server** — Maskit talks to third-party MCP servers; their responses must not be able to crash the proxy, ReDoS the masking engine, or poison persistent state.
- **Correctness bugs** (mask/unmask collisions, races, leaks) — same as any other software.

When reviewing security findings, classify by whether the attacker is (a) the local user themselves [out of scope], (b) a malicious upstream MCP server [in scope], or (c) a webpage in the user's browser / a remote OAuth peer [in scope].

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

4. **Web UI** (`web/app.py`, Starlette on port 9473) — Dashboard for viewing tool schemas, managing masking rules, trying out tools, and inspecting the traffic audit log (lazy-loaded, paginated).

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

### Traffic audit log (`traffic/`)

Tool-call records are persisted to a **separate** SQLite database (`~/.maskit/traffic.db`, configurable via `MASKIT_TRAFFIC_DB_PATH`) so rotation/vacuum is isolated and a corrupt traffic DB can't kill masking config.

- **`TrafficStore` (`traffic/store.py`)** — async aiosqlite wrapper. Opens with `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` for low-latency batched writes (WAL is critical here — the flush loop writes every 1s and rotation deletes are concurrent with reads from the GET endpoint). Unmasked args + unmasked response columns are encrypted at rest using the shared Fernet key from `security.TokenEncryption`. Masked args/response columns are plaintext (safe to read without the key).
- **`TrafficBuffer` (`traffic/buffer.py`)** — process-wide in-memory queue. `_intercept_response` (and the two block paths in `_intercept_request`) call `target.traffic_buffer.append(...)` synchronously on **terminal state only** — there are no pending/in-flight rows. `_traffic_flush_loop` in `__main__.py` drains the buffer to the store every 1s. This mirrors the `MaskingEngine._pending_writes` + `_flush_loop` idiom.
- **Rotation** — `_traffic_rotation_loop` enforces a global row cap (`MASKIT_TRAFFIC_MAX_ROWS`, default 10000) every 5 minutes by deleting the oldest rows beyond the cap.
- **Lazy UI** — there is no WebSocket stream. The dashboard fetches pages on demand via `GET /api/targets/{target_name}/traffic?limit=&before=<id>`. The endpoint flushes the buffer before reading so the response reflects the latest writes.
- **Status values** — `ok`, `error`, `blocked`. Blocked entries (hidden tool or guardrail violation) record the unmasked args (encrypted) and put the block reason into `masked_response`.

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

Two SQLite databases:

**`~/.maskit/store.db`** (masking config + state):
- `mappings` — alias ↔ real_value (persists across restarts so the same real value always gets the same alias)
- `rules` — masking rules created via Web UI (merged with config-file rules at startup), supports `action` column (`mask` or `strip`)
- `response_mappers` — output mapper configs (regex or json_field_mask) with optional `config` JSON column
- `hidden_tools` — tools hidden per server (blocked from agent access)
- `guardrails` — argument validation rules that block tool calls matching dangerous patterns
- `injections` — argument injection rules that inject/override values before forwarding
- `mcp_servers` — marketplace and custom servers (id, name, config JSON, active flag). Used for both marketplace installs and custom targets added via the UI

**`~/.maskit/traffic.db`** (audit log, separate file by design):
- `traffic` — one row per terminal-state tool call. Columns: `id`, `ts`, `target_name`, `tool_name`, `request_id`, `status`, `duration_ms`, `args_enc` (BLOB, Fernet), `response_enc` (BLOB, Fernet), `masked_args` (TEXT), `masked_resp` (TEXT). Indexed on `(target_name, id DESC)`.

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

Shared OAuth 2.1 callback server running on port 3131. Used by HTTP upstream targets that require OAuth (e.g., Slack). The callback server is started once in `__main__.py` and shared across all targets. OAuth tokens are stored per-server at `{store_dir}/oauth/{server_id}.json`.

### Bind host

All servers (web, MCP, OAuth callback) bind to the address in `MASKIT_HOST` env var (default `127.0.0.1`). The Dockerfile sets this to `0.0.0.0` so the container is accessible from the host.

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
- `GET /api/targets/{target_name}/traffic?limit=&before=<id>` — paginated audit log (cursor pagination; newest first; flushes pending buffer before reading)

Marketplace routes:

- `GET /api/marketplace` — catalog with install/active status
- `POST /api/marketplace/install` — install a server from catalog
- `POST /api/marketplace/activate` — reactivate a previously installed server
- `POST /api/marketplace/deactivate` — disconnect and deactivate

Custom target routes:

- `GET /api/custom-targets` — list custom targets
- `POST /api/custom-targets` — add a new custom target
- `POST /api/custom-targets/{target_id}/activate` — activate a deactivated custom target
- `POST /api/custom-targets/{target_id}/deactivate` — deactivate a custom target (keeps config)
- `POST /api/custom-targets/{target_id}/delete` — permanently remove a custom target

Server list routes:

- `GET /api/targets` — list all servers (active AND inactive) with runtime state merged from database

### Server lifecycle states

Servers can be in three states:
1. **Active** — Connected and running, appears in "Active Servers" section
2. **Inactive** — Disconnected but config retained in database, appears in "Inactive Servers" section, can be reactivated
3. **Deleted** — Permanently removed from database (custom servers only)

The Servers page (`/`) shows both active and inactive servers in separate sections. Users can:
- **Deactivate** any server (marketplace or custom) to temporarily disconnect it
- **Activate** any inactive server to reconnect using stored configuration
- **Delete** custom servers permanently (marketplace servers can only be deactivated)
- **View details** of inactive servers to see their configuration

### Container runtime compatibility

Maskit auto-detects container runtimes (Docker, Podman, nerdctl, Finch) for containerized MCP servers:

- Detection happens at startup (`container.py` module)
- Commands starting with `docker` are automatically substituted with detected runtime
- Optional override via `container_runtime` config field in `maskit.yaml`
- Example: `docker run mcp-server` → `podman run mcp-server` (if Podman is detected)
- Logs show detected/configured runtime at startup

This makes containerized marketplace servers work across different environments without user intervention.
