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

Tools can be hidden per-target via the Web UI. Hidden tools are stored in the `hidden_tools` SQLite table and loaded into `TargetState.hidden_tools` at startup. When an agent calls a hidden tool, the proxy returns a `METHOD_NOT_FOUND` error without forwarding to upstream.

### Text parsing (`masking/parsing.py`)

The `try_parse_structured` utility attempts JSON first, then falls back to `ast.literal_eval` for Python repr strings (common in some MCP tool responses). Results are serialized back in their original format after masking.

### Persistence

SQLite database (default `~/.maskit/store.db`) with tables:
- `mappings` — alias ↔ real_value (persists across restarts so the same real value always gets the same alias)
- `rules` — masking rules created via Web UI (merged with config-file rules at startup)
- `response_mappers` — output mapper configs (regex or json_field_mask) with optional `config` JSON column
- `hidden_tools` — tools hidden per target (blocked from agent access)

## Configuration

`maskit.yaml` at project root. Upstream supports `stdio` transport (spawns child process) and `http` transport (connects to remote MCP server with optional OAuth 2.1).

## Web UI API

All API routes are scoped per target: `/api/targets/{target_name}/...`

- `GET /api/targets/{target_name}/tools` — cached tool schemas
- `POST /api/targets/{target_name}/tools/call` — invoke a tool through the proxy (used by "Try it out")
- `GET/POST/PUT/DELETE /api/targets/{target_name}/rules` — masking rule CRUD
- `GET/POST/PUT/DELETE /api/targets/{target_name}/mappers` — response mapper CRUD
- `GET /api/targets/{target_name}/mappings` — current alias mappings
- `GET/POST /api/targets/{target_name}/hidden_tools` — hide/unhide tools from the agent
- `WS /ws/traffic` — live traffic stream
