<p align="center">
  <img src="assets/icon.png" alt="Maskit" width="120">
</p>

<h1 align="center">Maskit</h1>

<p align="center">
  <em>Drop-in MCP proxy that keeps your secrets out of the context window.</em>
</p>

---

## Why

AI coding agents see everything your MCP tools return — database hostnames, API keys, emails, internal URLs. Maskit sits between the agent and the real MCP server, replacing sensitive values with opaque aliases (`host_1`, `email_2`) so the model never sees the real data.

## How it works

```
AI Host (Claude Code, etc.)
    │ HTTP (:9474/mcp) or stdio
    ▼
  Maskit  ──── Web dashboard (http://127.0.0.1:9473)
    │ stdio / http
    ▼
Real MCP Server
```

- Tool responses are intercepted and matched against masking rules and response mappers
- Matched field values are replaced with stable aliases (same value always gets the same alias)
- Fields can be stripped entirely from responses (the agent never sees them)
- When the agent passes an alias back in a tool call, Maskit swaps in the real value before forwarding
- Argument guardrails block tool calls whose arguments match dangerous patterns (e.g., `DROP TABLE`)
- Argument injections silently inject or override values before forwarding (e.g., force `read_only: true`)
- Tools can be hidden per-server, blocking agent access entirely

## Install

```bash
# Requires Python 3.10+
git clone https://github.com/AminMal/maskit.git
cd maskit
uv sync
```

## Usage

1. Create a config file (e.g. `maskit.yaml`):

```yaml
upstream:
  transport: stdio
  command: uvx
  args: ["your-mcp-server"]

web_port: 9473
mcp_port: 9474
store_path: "~/.maskit/store.db"

rules:
  - tool_name: "get_connection"
    field_path: "host"
```

For HTTP upstream with OAuth (e.g. Slack):

```yaml
upstream:
  transport: http
  url: "https://mcp.slack.com/mcp"
  oauth:
    client_id: "your-client-id"
    callback_port: 3118

web_port: 9473
mcp_port: 9474
store_path: "~/.maskit/slack-store.db"

rules: []
```

2. Run:

```bash
maskit                     # uses ./maskit.yaml (or starts empty if no config)
maskit config.yaml         # custom path
```

You can also run without a config file — just start `maskit` and add servers through the marketplace or custom servers UI.

3. Connect your AI agent to Maskit's MCP endpoint (per server):

```bash
claude mcp add --scope project maskit-time --transport http http://localhost:9474/time/mcp
claude mcp add --scope project maskit-slack --transport http http://localhost:9474/slack/mcp
```

## Docker

```bash
docker build -t maskit .
docker run -p 9473:9473 -p 9474:9474 -p 3131:3131 maskit
```

Mount a config file if needed:

```bash
docker run -p 9473:9473 -p 9474:9474 -p 3131:3131 \
  -v ./maskit.yaml:/app/maskit.yaml \
  maskit
```

Ports:
- **9473** — Web dashboard
- **9474** — MCP endpoint (where AI agents connect)
- **3131** — OAuth callback (for servers requiring OAuth)

The container binds to `0.0.0.0` by default. Set `MASKIT_HOST` to override.

## Marketplace

The dashboard includes a marketplace for installing pre-configured MCP servers with one click. Browse the catalog, provide any required credentials, and the server is connected immediately — no config file edits needed.

Installed servers can be deactivated (paused) and reactivated without re-entering credentials.

## Custom Servers

You can also add arbitrary MCP servers at runtime through the dashboard. Specify a name, transport (stdio or http), command/URL, and optional environment variables. Custom servers are persisted and reconnected on restart.

## Web Dashboard

Open `http://127.0.0.1:9473` to:

- Browse and manage multiple upstream MCP servers
- Install servers from the marketplace catalog
- Add custom servers at runtime (no config file needed)
- Browse tool schemas from upstream servers
- Hide tools from the agent (blocked calls return an error)
- Create and manage masking rules (mask or strip fields)
- Create and manage response mappers (regex or JSON field mask)
- Configure argument guardrails to block dangerous tool calls
- Configure argument injections to force safe defaults
- Try out tools directly from the UI
- View live traffic and current alias mappings

## Configuration

Maskit supports multiple upstream servers in a single config:

```yaml
targets:
  time:
    upstream:
      transport: stdio
      command: uvx
      args: ["mcp-server-time"]
    rules: []

  slack:
    upstream:
      transport: http
      url: "https://mcp.slack.com/mcp"
      oauth:
        client_id: "your-client-id"
        callback_port: 3118
    rules:
      - tool_name: "send_message"
        field_path: "channel_id"
      - tool_name: "get_user"
        field_path: "ssn"
        action: "strip"
    guardrails:
      - tool_name: "run_sql"
        pattern: "DROP TABLE"
        message: "Destructive SQL is not allowed"
    injections:
      - tool_name: "run_sql"
        argument_name: "read_only"
        value: "true"
        mode: "set"

web_port: 9473
mcp_port: 9474
store_path: "~/.maskit/store.db"
```

Each server gets its own MCP endpoint at `http://localhost:{mcp_port}/{server_name}/mcp`.

Or a single upstream (legacy format):

| Field | Description |
|-------|-------------|
| `upstream.transport` | `stdio` or `http` |
| `upstream.command` / `args` | Command to spawn (stdio mode) |
| `upstream.url` | Server URL (http mode) |
| `upstream.oauth` | OAuth 2.1 settings (http mode) |
| `web_port` | Dashboard port (default: 9473) |
| `mcp_port` | MCP HTTP endpoint port (default: 9474) |
| `store_path` | SQLite database path |
| `rules` | List of `{tool_name, field_path, alias_prefix?, action?}` |
| `guardrails` | List of `{tool_name?, argument_name?, match_type?, pattern, message?}` |
| `injections` | List of `{tool_name?, argument_name, value, mode?}` |

### Rules

Rules define fields to mask or strip in tool responses:

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to apply to (`*` for all) |
| `field_path` | Dot-notation path (e.g. `user.email`) |
| `alias_prefix` | Custom alias prefix (default: `_masked_{field}`) |
| `action` | `mask` (default) or `strip` (removes field entirely) |

### Guardrails

Guardrails block tool calls whose arguments match patterns:

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to apply to (`*` for all, default) |
| `argument_name` | Argument to check (`*` scans all values recursively, default) |
| `match_type` | `contains` (default), `equals`, or `regex` |
| `pattern` | Pattern to match against |
| `message` | Error message returned to the agent |

### Injections

Injections silently inject or override argument values:

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to apply to (`*` for all, default) |
| `argument_name` | Argument key to set |
| `value` | JSON-encoded value (e.g. `"true"`, `"100"`, `"\"hello\""`) |
| `mode` | `set` (always override, default), `default` (only if absent), `append` |

### Response Mappers

Response mappers provide pattern-based masking on tool output text. Two types:

| Type | Description |
|------|-------------|
| `regex_replace` | Apply a regex to the text response; matching groups are replaced with aliases |
| `json_field_mask` | Target a specific dot-notation path in parsed JSON/repr output |

Mappers are created per-tool via the dashboard and apply to all future responses from that tool.

## Development

```bash
uv run pytest tests/ -v
```
