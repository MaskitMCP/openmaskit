# Maskit

An MCP proxy that masks sensitive data in tool responses before they reach your AI agent, and unmasks them transparently when the agent uses those values in subsequent tool calls.

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

- Tool responses are intercepted and matched against masking rules
- Matched field values are replaced with stable aliases (same value always gets the same alias)
- When the agent passes an alias back in a tool call, Maskit swaps in the real value before forwarding

## Install

```bash
# Requires Python 3.10+
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
uv run maskit              # uses ./maskit.yaml
uv run maskit config.yaml  # custom path
```

3. Connect your AI agent to Maskit's MCP endpoint:

```bash
claude mcp add --scope project maskit --transport http http://localhost:9474/mcp
```

## Web Dashboard

Open `http://127.0.0.1:9473` to:

- Browse tool schemas from the upstream server
- Create and manage masking rules interactively
- Try out tools directly from the UI
- View live traffic and current alias mappings

## Configuration

| Field | Description |
|-------|-------------|
| `upstream.transport` | `stdio` or `http` |
| `upstream.command` / `args` | Command to spawn (stdio mode) |
| `upstream.url` | Server URL (http mode) |
| `upstream.oauth` | OAuth 2.1 settings (http mode) |
| `web_port` | Dashboard port (default: 9473) |
| `mcp_port` | MCP HTTP endpoint port (default: 9474) |
| `store_path` | SQLite database path |
| `rules` | List of `{tool_name, field_path, alias_prefix?}` |

## Development

```bash
uv run pytest tests/ -v
```
