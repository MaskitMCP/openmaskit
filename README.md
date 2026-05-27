<p align="center">
  <img src="assets/icon.png" alt="Maskit" width="120">
</p>

<h1 align="center">Maskit</h1>

<p align="center">
  <em>Secure MCP proxy that keeps your secrets out of AI context windows</em>
</p>

<p align="center">
  <strong>⚠️ Early Stage Project — Not Production-Ready</strong><br>
  Maskit is under active development. Expect breaking changes and bugs.<br>
  Contributions and feedback are welcome!
</p>

---

## Overview

AI coding assistants see everything your MCP tools return — production database hosts, API keys, customer emails, internal infrastructure. Maskit sits between your AI and MCP servers, replacing sensitive values with safe aliases (`host_1`, `email_2`, `api_key_1`) so models never see real data.

**Key Features:**
- 🎭 **Data masking** — Sensitive values replaced with stable aliases
- 🔐 **Token encryption** — OAuth credentials encrypted at rest (Fernet AES-128)
- 🛡️ **Guardrails** — Block dangerous operations before they reach servers
- 💉 **Injections** — Force safe defaults (e.g., `read_only: true`)
- 🏪 **Marketplace** — One-click server installation with OAuth support
- 📊 **Dashboard** — Visual tool management and live traffic monitoring

## Security Features

### 🎭 Data Masking
- **Input masking**: Sensitive argument values replaced before AI sees them
- **Output masking**: Tool responses automatically masked via rules or regex patterns
- **Stable aliasing**: Same value always gets same alias across sessions
- **Field stripping**: Remove sensitive fields entirely (SSNs, credit cards, etc.)

### 🛡️ Guardrails & Injections
- **Guardrails**: Block dangerous operations (`DROP TABLE`, `rm -rf`, force push)
- **Injections**: Silently enforce safe defaults (`read_only: true`, connection limits)
- **Hidden tools**: Remove tools from agent access without deleting config

### 🔐 Token Security
- **Encrypted storage**: OAuth tokens encrypted at rest with Fernet (AES-128)
- **Encryption key**: Stored at `~/.maskit/.key` (auto-generated on first run)
- **Auto-refresh**: Expired OAuth tokens automatically refreshed via backend
- **Path validation**: Server IDs validated to prevent directory traversal

**⚠️ Important: Backup Your Encryption Key**

Your OAuth tokens are encrypted using a key at `~/.maskit/.key`. If you lose this key, **you will lose access to all stored OAuth tokens** and will need to re-authenticate.

```bash
# Backup your encryption key (KEEP THIS SECURE!)
cp ~/.maskit/.key ~/.maskit/.key.backup

# Or use an environment variable for key management
export MASKIT_ENCRYPTION_KEY=$(cat ~/.maskit/.key)
```

**Key priority:**
1. `MASKIT_ENCRYPTION_KEY` environment variable (recommended for production)
2. `~/.maskit/.key` file (auto-generated for local use)
3. New key generated if neither exists

## Use Cases

✅ **Safe for:**
- Local development with production tool access
- Prototyping AI workflows without exposing secrets
- Testing MCP integrations with sensitive data

⚠️ **Not recommended for:**
- Production systems handling regulated data (PII, PHI, PCI) without hardening
- Compliance-critical environments requiring audit trails (SOC 2, HIPAA)
- Multi-tenant deployments (designed for single-user local use)

## Experimental Features

### 🧪 Dynamic Client Registration (DCR)

**Status: Experimental** — May not work with all OAuth providers

When adding custom HTTP servers with OAuth, Maskit offers two modes:
- **Dynamic Registration**: Automatically discovers OAuth endpoints and registers a unique client
- **Manual Credentials**: Provide existing OAuth application credentials (recommended for production)

**Known limitations:**
- DCR support varies significantly by OAuth provider
- Some providers require pre-approval, registration tokens, or specific scopes
- Connection failures may occur with non-standard OAuth implementations
- **Manual mode is more reliable** if you have existing OAuth credentials

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

## Quick Start

### Install from source

```bash
git clone https://github.com/AminMal/maskit.git
cd maskit
uv sync
```

### Run

```bash
maskit                    # Start with empty config (add servers via UI)
maskit config.yaml        # Or use a config file
```

Open `http://127.0.0.1:9473` for the dashboard.

## Configuration

### Config File (Optional)

Create `maskit.yaml` for pre-configured servers:

```yaml
targets:
  time:
    upstream:
      transport: stdio
      command: uvx
      args: ["mcp-server-time"]
    rules:
      - tool_name: "get_time"
        field_path: "timezone"

  slack:
    upstream:
      transport: http
      url: "https://mcp.slack.com/mcp"
      oauth:
        client_id: "your-client-id"
    guardrails:
      - tool_name: "*"
        pattern: "DROP TABLE"
        message: "Destructive SQL blocked"
    injections:
      - tool_name: "query_db"
        argument_name: "read_only"
        value: "true"
        mode: "set"

web_port: 9473
mcp_port: 9474
oauth_port: 3131

# Optional: Override container runtime (auto-detects docker/podman/nerdctl/finch)
# container_runtime: "podman"
```

**Or skip the config** — install servers via the marketplace or add custom servers through the UI.

### CLI Options

```bash
maskit --help                          # Show help
maskit --version                       # Show version
maskit --web-port 8080                 # Custom dashboard port
maskit -w 8080 -m 8081 -o 8082         # Override multiple ports
maskit --store-path /data/maskit.db    # Custom database location
maskit config.yaml -w 9000             # Config + override
```

### Environment Variables

```bash
MASKIT_HOST=0.0.0.0                    # Bind address (default: 127.0.0.1)
MASKIT_ENCRYPTION_KEY=<base64-key>     # Override token encryption key
MASKIT_LOG_FORMAT=json                 # JSON logging for production
MASKIT_SHUTDOWN_TIMEOUT=30             # Graceful shutdown timeout (seconds)
```

### Backup and Data Safety

**What to backup:**

1. **Encryption key**: `~/.maskit/.key` (required to decrypt OAuth tokens)
2. **Database**: `~/.maskit/store.db` (masking rules, aliases, server configs)

```bash
# Backup both critical files
cp ~/.maskit/.key ~/backups/maskit-key.backup
cp ~/.maskit/store.db ~/backups/maskit-db-$(date +%Y%m%d).db

# Restore from backup
cp ~/backups/maskit-key.backup ~/.maskit/.key
cp ~/backups/maskit-db-20260524.db ~/.maskit/store.db
```
### Production Features

**Health Endpoint:**
```bash
curl http://127.0.0.1:9473/health
# Returns: { "status": "healthy", "uptime_seconds": 123.45, "targets": [...] }
```

**JSON Logging:**
```bash
MASKIT_LOG_FORMAT=json maskit  # For log aggregation systems
```

**Graceful Shutdown:**
Maskit drains in-flight requests, flushes database, and exits cleanly on SIGINT/SIGTERM.

### Connect AI Agents

The "Connect Agent" in the dashboard helps you connect your MCP servers to your AI agents.

## Container Runtime Support

Maskit automatically detects and works with different container runtimes:

- **Auto-detection**: Automatically detects Docker, Podman, nerdctl, or Finch at startup
- **Transparent substitution**: Commands starting with `docker` are automatically converted to use your installed runtime
- **Configuration override**: Optionally specify runtime in `maskit.yaml` with `container_runtime: "podman"`

**Example:** If you have Podman installed, marketplace servers like `docker run ghcr.io/example/mcp-server` automatically become `podman run ghcr.io/example/mcp-server`.

This means containerized MCP servers work seamlessly regardless of which container runtime you use!

## Docker

```bash
docker build -t maskit .
docker run -p 9473:9473 -p 9474:9474 -p 3131:3131 maskit
```

**Ports:** 9473 (dashboard), 9474 (MCP), 3131 (OAuth callback)

⚠️ **Limitation:** Docker only supports HTTP-based MCP servers. For stdio servers (`uvx`, `npx`), run Maskit natively.

## Dashboard Features

Open `http://127.0.0.1:9473` to:

- **Marketplace**: Install pre-configured servers (Slack, GitHub, etc.) with OAuth
- **Custom servers**: Add stdio/HTTP servers at runtime
- **Server lifecycle**: Deactivate/activate servers without losing configuration, permanently delete custom servers
- **Inactive servers**: View and manage deactivated servers in a separate section
- **Tool management**: Browse schemas, hide tools, test tool calls
- **Masking rules**: Configure input/output masking per tool
- **Guardrails**: Block dangerous operations by pattern
- **Injections**: Force safe argument defaults
- **Live traffic**: Monitor tool calls and alias mappings in real-time

### Server States

Servers can be in three states:
- **Active**: Connected and running
- **Inactive**: Disconnected but configuration retained, can be reactivated
- **Deleted**: Permanently removed (custom servers only)

The Servers page shows both active and inactive servers in separate sections. You can temporarily deactivate any server (marketplace or custom) without losing its configuration, then reactivate it later with one click.

## Configuration Reference

### Rules (Input/Output Masking)

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to apply to (`*` = all tools) |
| `field_path` | Dot-notation path (e.g., `user.email`, `connection.host`) |
| `alias_prefix` | Custom prefix (default: `_masked_{field}`) |
| `action` | `mask` (replace with alias) or `strip` (remove entirely) |

### Guardrails (Block Dangerous Operations)

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to protect (`*` = all, default) |
| `argument_name` | Argument to check (`*` = scan all recursively, default) |
| `match_type` | `contains`, `equals`, or `regex` (default: `contains`) |
| `pattern` | Pattern to block (e.g., `DROP TABLE`, `rm -rf`) |
| `message` | Error message shown to agent |

### Injections (Force Safe Defaults)

| Field | Description |
|-------|-------------|
| `tool_name` | Tool to inject into (`*` = all, default) |
| `argument_name` | Argument key to set |
| `value` | JSON-encoded value (`"true"`, `"100"`, `"\"hello\""`) |
| `mode` | `set` (always), `default` (if missing), `append` (for arrays/strings) |

### Response Mappers (Pattern-Based Masking)

| Type | Description |
|------|-------------|
| `regex_replace` | Regex pattern masking (e.g., `\b[A-Z0-9]{32}\b` for API keys) |
| `json_field_mask` | JSON path masking (e.g., `response.data.token`) |

## Architecture

```
┌─────────────────────┐
│  AI Agent           │
│  (Claude/Cursor)    │
└──────────┬──────────┘
           │ HTTP :9474/{server}/mcp
           ▼
┌─────────────────────┐      ┌──────────────┐
│  Maskit Proxy       │◄────►│  Dashboard   │
│                     │      │  :9473       │
│  • Mask/unmask      │      └──────────────┘
│  • Guardrails       │
│  • Token encryption │
│  • Traffic logs     │
└──────────┬──────────┘
           │ stdio/HTTP
           ▼
┌─────────────────────┐
│  Real MCP Server    │
│  (Slack, GitHub,    │
│   Postgres, etc.)   │
└─────────────────────┘
```

## Development

```bash
git clone https://github.com/AminMal/maskit.git
cd maskit
uv sync
uv run pytest tests/ -v
```

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
