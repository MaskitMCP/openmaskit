<p align="center">
  <img src="assets/icon.png" alt="OpenMaskit" width="120">
</p>

<h1 align="center">OpenMaskit&trade;</h1>

<p align="center">
  <em>Secure MCP proxy that keeps your secrets out of AI context windows</em>
</p>

<p align="center">
  <strong>⚠️ Early stage — expect breaking changes.</strong>
</p>

---

## What it does

AI coding assistants see everything your MCP tools return — production hostnames, API keys, customer emails. OpenMaskit sits between your AI and your MCP servers and replaces sensitive values with stable aliases (`host_1`, `email_2`, `api_key_1`) so the model never sees the real data. When the agent passes an alias back in a tool call, OpenMaskit swaps in the real value before forwarding.

It also lets you block dangerous tool calls (guardrails), force safe defaults (injections), hide tools from agents, and install pre-configured servers from a marketplace.

<p align="center">
  <video src="https://github.com/user-attachments/assets/49d862ed-2f51-4bfd-b9cb-979e43e0eb31"
         autoplay loop muted playsinline
         width="720">
    Your browser doesn't support inline video.
    <a href="https://github.com/user-attachments/assets/49d862ed-2f51-4bfd-b9cb-979e43e0eb31">Watch the masking demo</a>.
  </video>
</p>
<p align="center">
  <sub><em>Mask sensitive fields before they reach the model.</em></sub>
</p>

<p align="center">
  <video src="https://github.com/user-attachments/assets/0329b4b1-3023-4065-a4b9-02f9ecf9f6a9"
         autoplay loop muted playsinline
         width="720">
    Your browser doesn't support inline video.
    <a href="https://github.com/user-attachments/assets/0329b4b1-3023-4065-a4b9-02f9ecf9f6a9">Watch the guardrail demo</a>.
  </video>
</p>
<p align="center">
  <sub><em>Block dangerous tool calls with guardrails.</em></sub>
</p>

```
AI Agent (Claude, Cursor, …)
    │  HTTP :9474/{server}/mcp
    ▼
  OpenMaskit  ──  Dashboard :9473
    │  stdio / HTTP
    ▼
Real MCP Server
```

## Quick start

OpenMaskit ships as a Python CLI. Requires Python 3.10+ — if you don't have it, the recommended installer (`uvx`) will fetch a compatible one for you.

**With [uv](https://docs.astral.sh/uv/) (recommended):**

```bash
# Install uv if you don't have it (one line, no Python prereq):
curl -LsSf https://astral.sh/uv/install.sh | sh

# Then run OpenMaskit:
uvx openmaskit
```

`uvx` downloads a compatible Python (if needed), installs OpenMaskit in an isolated environment, and runs it — one command, no venv to manage.

**With [pipx](https://pipx.pypa.io/) (alternative):**

```bash
pipx install openmaskit
openmaskit
```

`pipx` doesn't auto-fetch Pythons, so you'll need a 3.10+ interpreter available first.

Then open the dashboard at **http://127.0.0.1:9473** — add servers from the marketplace, connect your AI agent with one click, and configure masking from the UI.

## Configuration

OpenMaskit runs with no config at all — add servers from the dashboard.

If you'd rather pre-declare servers, drop a `openmaskit.yaml` next to where you run it:

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

  postgres:
    upstream:
      transport: stdio
      command: docker
      args: ["run", "-i", "--rm", "-e", "DATABASE_URI", "crystaldba/postgres-mcp"]
      env:
        DATABASE_URI: postgresql://user:pass@localhost:5432/mydb
    guardrails:
      - pattern: "DROP TABLE"
        message: "Destructive SQL blocked"

  datadog:
    upstream:
      transport: http
      url: https://mcp.datadoghq.eu/api/unstable/mcp-server/mcp
      headers:
        DD-API-KEY: replace-with-your-key
        DD-APPLICATION-KEY: replace-with-your-key

# Optional overrides (defaults shown)
web_port: 9473
mcp_port: 9474
oauth_port: 3131
# container_runtime: podman    # auto-detected from docker/podman/nerdctl/finch
```

### CLI

```bash
openmaskit                              # use ./openmaskit.yaml (or start empty)
openmaskit path/to/config.yaml          # custom config
openmaskit -c path/to/config.yaml       # same, via flag
openmaskit -w 9473 -m 9474 -o 3131      # override ports
openmaskit -s ~/.openmaskit/store.db        # override SQLite path
openmaskit --version
```

### Environment variables

| Variable | Purpose |
|---|---|
| `OPENMASKIT_HOST` | Bind address (default `127.0.0.1`; Docker image uses `0.0.0.0`) |
| `OPENMASKIT_ENCRYPTION_KEY` | Override the at-rest encryption key (otherwise read from `~/.openmaskit/.key`) |
| `OPENMASKIT_LOG_FORMAT` | `text` (default) or `json` |
| `OPENMASKIT_SHUTDOWN_TIMEOUT` | Graceful shutdown deadline in seconds (default 30) |
| `OPENMASKIT_TRAFFIC_DB_PATH` | Path to the traffic audit database (default `~/.openmaskit/traffic.db`) |
| `OPENMASKIT_TRAFFIC_MAX_ROWS` | Cap on stored audit rows (default 10000, oldest evicted first) |
| `OPENMASKIT_ALLOWED_ORIGINS` | Comma-separated extra origins allowed to call `/api/*` |
| `OPENMASKIT_MAX_REQUEST_BYTES` | Max HTTP request body size in bytes for the dashboard and MCP endpoints (default 1 MiB). Oversized requests get a 413. |
| `OPENMASKIT_MAX_PARSE_BYTES` | Max length of an upstream text block (in chars) handed to the JSON / Python-repr parser (default 1 MiB). Oversized blocks skip parsing and fall through as plain text. |
| `OPENMASKIT_DISABLE_MARKETPLACE` | Set to `1` to opt out of all calls to `api.maskitmcp.com` (catalog, server detail, version check). Custom servers continue to work. |

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

- **Container runtime auto-detection** — Marketplace servers shipped as `docker run …` automatically run on Podman, nerdctl, or Finch if that's what you have. No flag needed; override with `container_runtime` in `openmaskit.yaml` if you want to pin a specific one.
- **Container lifecycle management** — When you deactivate, delete, or stop OpenMaskit, any containers it spawned are stopped with it. No orphaned containers sitting around using ports.
- **Stable aliases across restarts** — `prod-db.internal.net` always becomes `host_1`, the same alias your agent saw last week. Aliases are persisted, so multi-turn conversations stay coherent.
- **Encrypted traffic audit log** — Every tool call is recorded with its unmasked args and response, Fernet-encrypted at rest. Lazy-loaded from the UI on demand and capped at 10k rows by default.
- **Two OAuth install paths today** — Marketplace servers can ship as **BYO** (paste your own `client_id`/`client_secret`, OpenMaskit runs the flow locally) or **DCR** (OpenMaskit registers a client with the provider automatically). DCR discovery follows the MCP authorization spec — it probes the MCP URL, reads the `WWW-Authenticate` challenge for the protected-resource metadata link, and follows it to the authorization server, which can live at a different host than the MCP endpoint (Supabase, Atlassian). The "Re-authorize" button on each server card runs a fresh flow when tokens expire. Setup guides for the BYO ones live at [openmaskit.com/connect](https://www.openmaskit.com/connect/). A third **hosted-broker** path (zero-setup, with the OAuth code exchange handled by `auth.maskitmcp.com`) is fully implemented but **currently disabled** while we work through every security aspect of it — we'd rather ship it later and right than early and questionable.
- **Multi-tenant servers in the marketplace** — Catalog entries that need a user-supplied identifier in the upstream URL (Supabase `project_ref`, similar patterns for project- or workspace-scoped servers) declare a `meta.params` list; the install modal collects them and the install handler URL-encodes them onto the upstream URL. Discovery and DCR then run against the resolved URL so the authorization server sees the right resource identifier.
- **API-key auth for non-OAuth HTTP servers** — Marketplace and custom HTTP servers can authenticate with static headers (Datadog `DD-API-KEY`, Stripe `Authorization: Bearer`, etc.). Header values are stored Fernet-encrypted alongside everything else.
- **Hot add/remove servers** — Marketplace installs, custom server adds, deactivations, and deletes all happen live. No restart needed.
- **Argument guardrails and injections** — Block `DROP TABLE` before it leaves your machine; silently inject `read_only: true` on every database call (if supported by the underlying MCP server).
- **Field stripping** — Some fields shouldn't be aliased, they should just be gone. SSNs, credit cards — strip them from responses entirely.
- **Localhost-safe by default** — `Origin` allow-listing, CSRF protection, and OAuth `state` validation are on out of the box, so a malicious webpage can't reach into your local OpenMaskit.

## Docker

```bash
docker build -t openmaskit .
docker run -p 9473:9473 -p 9474:9474 -p 3131:3131 openmaskit
```

The container supports HTTP-based MCP servers. For stdio servers (`uvx`, `npx`), run OpenMaskit natively.

## Data safety

Two files matter:

- `~/.openmaskit/.key` — encrypts OAuth tokens, the traffic audit log, and stored server configs (env vars, HTTP headers, OAuth secrets). Worth backing up — without it, the stored credentials can't be decrypted and servers will need to be re-installed.
- `~/.openmaskit/store.db` — masking rules, aliases, server configs.

`~/.openmaskit/traffic.db` is the audit log; safe to drop.

For production-style setups, hold the key in `OPENMASKIT_ENCRYPTION_KEY` instead of on disk.

## Telemetry

OpenMaskit generates a random 25-character anonymous installation ID on first run, stored at `~/.openmaskit/.installation_id`. The ID, along with the running version (in `User-Agent`), is sent to `api.maskitmcp.com` on three endpoints: catalog browse, server detail, and version check. The backend uses it to validate that requests come from a real OpenMaskit install and to count active installations.

**That's it.** No tool calls, masking rules, MCP server contents, response bodies, OAuth tokens, or usage events are sent. There's no account, no email, no IP-based linking. The backend is only contacted when the marketplace is used.

**To opt out**, set `OPENMASKIT_DISABLE_MARKETPLACE=1`. Catalog browse and server detail return empty; custom HTTP/stdio servers continue to work normally.

See [CHANGELOG.md](CHANGELOG.md) for upgrade notes between versions.

## Contributing

Bug reports, feature requests, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

To run from source instead of a published wheel:

```bash
git clone https://github.com/MaskitMCP/openmaskit.git
cd openmaskit
uv sync
uv run openmaskit
```

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"OpenMaskit"™ and the OpenMaskit logo are trademarks of Amin Malekloo. The Apache 2.0 license does not grant trademark rights — see [TRADEMARKS.md](TRADEMARKS.md) for permitted uses (forks must use a different name; "compatible with OpenMaskit" is fine).
