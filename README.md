<p align="center">
  <img src="assets/icon.png" alt="Maskit" width="120">
</p>

<h1 align="center">Maskit</h1>

<p align="center">
  <em>Secure MCP proxy that keeps your secrets out of AI context windows</em>
</p>

<p align="center">
  <strong>⚠️ Early stage — expect breaking changes.</strong>
</p>

---

## What it does

AI coding assistants see everything your MCP tools return — production hostnames, API keys, customer emails. Maskit sits between your AI and your MCP servers and replaces sensitive values with stable aliases (`host_1`, `email_2`, `api_key_1`) so the model never sees the real data. When the agent passes an alias back in a tool call, Maskit swaps in the real value before forwarding.

It also lets you block dangerous tool calls (guardrails), force safe defaults (injections), hide tools from agents, and install pre-configured servers from a marketplace.

```
AI Agent (Claude, Cursor, …)
    │  HTTP :9474/{server}/mcp
    ▼
  Maskit  ──  Dashboard :9473
    │  stdio / HTTP
    ▼
Real MCP Server
```

## Quick start

```bash
git clone https://github.com/AminMal/maskit.git
cd maskit
uv sync
uv run maskit
```

Then open the dashboard at **http://127.0.0.1:9473** — add servers from the marketplace, connect your AI agent with one click, and configure masking from the UI.

## Configuration

Maskit runs with no config at all — add servers from the dashboard.

If you'd rather pre-declare servers, drop a `maskit.yaml` next to where you run it:

```yaml
targets:
  time:
    upstream:
      transport: stdio
      command: uvx
      args: ["mcp-server-time"]
    rules:
      - tool_name: get_time
        field_path: timezone

  slack:
    upstream:
      transport: http
      url: https://mcp.slack.com/mcp
      oauth:
        client_id: your-client-id
    guardrails:
      - pattern: "DROP TABLE"
        message: "Destructive SQL blocked"
    injections:
      - tool_name: query_db
        argument_name: read_only
        value: "true"
        mode: set

# Optional overrides (defaults shown)
web_port: 9473
mcp_port: 9474
oauth_port: 3131
# container_runtime: podman    # auto-detected from docker/podman/nerdctl/finch
```

### CLI

```bash
maskit                              # use ./maskit.yaml (or start empty)
maskit path/to/config.yaml          # custom config
maskit -c path/to/config.yaml       # same, via flag
maskit -w 9473 -m 9474 -o 3131      # override ports
maskit -s ~/.maskit/store.db        # override SQLite path
maskit --version
```

### Environment variables

| Variable | Purpose |
|---|---|
| `MASKIT_HOST` | Bind address (default `127.0.0.1`; Docker image uses `0.0.0.0`) |
| `MASKIT_ENCRYPTION_KEY` | Override the at-rest encryption key (otherwise read from `~/.maskit/.key`) |
| `MASKIT_LOG_FORMAT` | `text` (default) or `json` |
| `MASKIT_SHUTDOWN_TIMEOUT` | Graceful shutdown deadline in seconds (default 30) |
| `MASKIT_TRAFFIC_DB_PATH` | Path to the traffic audit database (default `~/.maskit/traffic.db`) |
| `MASKIT_TRAFFIC_MAX_ROWS` | Cap on stored audit rows (default 10000, oldest evicted first) |
| `MASKIT_ALLOWED_ORIGINS` | Comma-separated extra origins allowed to call `/api/*` |

## Dashboard

Everything is configurable from the UI at `http://127.0.0.1:9473`:

- **Marketplace** — one-click install of pre-configured MCP servers (with OAuth where needed).
- **Custom servers** — add stdio or HTTP servers at runtime; deactivate or delete without losing config.
- **Tools** — browse schemas, try calls, hide tools from agents, set per-tool masking rules, regex output mappers, guardrails, and argument injections.
- **Traffic** — encrypted, paginated audit log of recent calls.

Connect an AI agent to a server with the "Connect Agent" button on its page — it generates the snippet for Claude Code, Cursor, VS Code, Windsurf, JetBrains, Codex, or OpenCode.

> 💡 **Built-in tutorials.** Each configuration panel in the dashboard has a small help icon next to its title. Click it for a guided, step-by-step walkthrough of input masking, output mappers, guardrails, injections, and hiding tools — no docs to dig through.

## Highlights

A few things worth knowing about:

- **Container runtime auto-detection** — Marketplace servers shipped as `docker run …` automatically run on Podman, nerdctl, or Finch if that's what you have. No flag needed; override with `container_runtime` in `maskit.yaml` if you want to pin a specific one.
- **Container lifecycle management** — When you deactivate, delete, or stop Maskit, any containers it spawned are stopped with it. No orphaned containers sitting around using ports.
- **Stable aliases across restarts** — `prod-db.internal.net` always becomes `host_1`, the same alias your agent saw last week. Aliases are persisted, so multi-turn conversations stay coherent.
- **Encrypted traffic audit log** — Every tool call is recorded with its unmasked args and response, Fernet-encrypted at rest. Lazy-loaded from the UI on demand and capped at 10k rows by default.
- **OAuth with Dynamic Client Registration** (experimental) — Adding an HTTP server that supports DCR? Maskit can discover its OAuth endpoints and register a client automatically. Manual credentials are also supported and more reliable for providers that don't fully implement DCR.
- **Hot add/remove servers** — Marketplace installs, custom server adds, deactivations, and deletes all happen live. No restart needed.
- **Argument guardrails and injections** — Block `DROP TABLE` before it leaves your machine; silently inject `read_only: true` on every database call.
- **Field stripping** — Some fields shouldn't be aliased, they should just be gone. SSNs, credit cards — strip them from responses entirely.
- **Localhost-safe by default** — `Origin` allow-listing, CSRF protection, and OAuth `state` validation are on out of the box, so a malicious webpage can't reach into your local Maskit.

## Docker

```bash
docker build -t maskit .
docker run -p 9473:9473 -p 9474:9474 -p 3131:3131 maskit
```

The container supports HTTP-based MCP servers. For stdio servers (`uvx`, `npx`), run Maskit natively.

## Data safety

Two files matter:

- `~/.maskit/.key` — encrypts OAuth tokens and the traffic audit log. **Back this up.** Lose it and you'll re-authenticate every server.
- `~/.maskit/store.db` — masking rules, aliases, server configs.

`~/.maskit/traffic.db` is the audit log; safe to drop.

For production-style setups, hold the key in `MASKIT_ENCRYPTION_KEY` instead of on disk.

## Contributing

Bug reports, feature requests, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

## License

MIT — see [LICENSE](LICENSE).
