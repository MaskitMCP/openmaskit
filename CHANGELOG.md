# Changelog

All notable changes to OpenMaskit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-06-05

This release bundles a security and correctness pass. Two breaking changes
worth surfacing up front: the dashboard API now requires a CSRF token + an
allowed `Origin` on mutating requests (CLI / script clients need to set both),
and the `mappings` table primary key migrated from `alias` to
`(target_name, alias)` so two targets with overlapping rule prefixes can
independently hold the same alias. The migration runs automatically on first
open of an existing `store.db`.

### Added
- HTTP body size cap via a new `BodySizeLimitMiddleware` on the dashboard and MCP endpoints (`OPENMASKIT_MAX_REQUEST_BYTES`, default 1 MiB; oversized → 413). Rejects by `Content-Length` and by actual byte count.
- CSRF token defense on mutating `/api/*` requests. Process-scoped random token served from `GET /api/csrf`, validated via `X-CSRF-Token`; dashboard JS attaches it automatically.
- Per-text-block parse cap on upstream tool responses (`OPENMASKIT_MAX_PARSE_BYTES`, default 1 MiB). Bounds memory from a malicious upstream returning a giant nested literal that would otherwise OOM the proxy via `ast.literal_eval`.

### Changed
- **BREAKING.** `mappings` primary key is now `(target_name, alias)`. Aliases are now namespaced per target; flush uses a new `persist_alias` so the engine's chosen alias is persisted verbatim instead of being silently renumbered by a separate store counter. Migration runs on first open of an existing `~/.openmaskit/store.db`.
- **BREAKING.** Mutating `/api/*` requests (POST/PUT/DELETE/PATCH) now require both an allowed `Origin` header and a valid `X-CSRF-Token`. Existing CLI / script clients hitting the dashboard API need to set both. The MCP endpoint (`:9474`) is unaffected — real MCP clients send neither.
- `store.db` now runs with `journal_mode=WAL` and `synchronous=NORMAL`, matching `traffic.db`. Removes write serialization between the alias flush loop and dashboard CRUD.
- Toggling a tool as hidden via the API now rejects names that don't exact-match an advertised tool (case-sensitive), with a 400 `unknown_tool` error. Unhide is unconditional so stale entries can be removed.

### Fixed
- Masking rules now fan out across list nestings — `categories.id` against `{"categories": [{"id": "a"}, {"id": "b"}]}` reaches both. Regex mappers also run on `structuredContent` string leaves, not just text blocks. Mapper preview matches live behavior.
- A bad `config_enc` / encrypted-traffic row used to raise out of every list query and break the entire Servers / Traffic page. Per-row decrypt now falls back to `None` so the dashboard stays loadable and orphan rows are visible for cleanup. Orphan rows (active in DB but not connected at startup, e.g. undecryptable config) are now surfaced in the Inactive section instead of vanishing.
- `ResponseDispatcher` waiter leaks: the HTTP handler now wraps register-send-wait in `try/finally` with a shielded `collect()` so a `send()` failure or task cancellation can't leave a waiter dangling for 120s. A duplicate register on the same request id wakes the orphan and logs a warning.

### Removed
- Dead `re.Pattern.search(test_str)` "TimeoutError" branch in mapper pre-validation. Python's stdlib `re` has never had a per-call timeout; that block never fired.

## [0.3.1] - 2026-06-03

### Fixed
- RFC 8414 OAuth authorization-server metadata: path-aware discovery (§3.1 inserts `/.well-known/...` between host and path for path-prefixed issuers, with the appended form as a secondary candidate), and `issuer` validation per §3.3. Fixes DCR against authorization servers that mount metadata under a path prefix.
- RFC 9728 protected-resource metadata: fall back to the root-form `/.well-known/oauth-protected-resource` when the path-scoped form 404s (SEP-985).
- RFC 7591 dynamic client registration: include `software_id` / `software_version` in the registration request, and surface the server's `error` / `error_description` fields on failure (§3.2.2) instead of a generic message.
- RFC 7592: capture and persist `registration_access_token` and `registration_client_uri` from the DCR response so future client-management calls have what they need.
- RFC 8252 §7.3 native-app loopback: prefer `http://127.0.0.1:3131/callback` as the canonical redirect URI; keep `http://localhost:3131/callback` registered alongside for compatibility with the existing BYO setup-guide narrative.
- DCR `token_endpoint_auth_method`: pick what the authorization server advertises (`client_secret_post` preferred when supported, `none` for public clients) instead of always assuming `client_secret_basic`.

## [0.3.0] - 2026-06-03

### Added
- Spec-compliant MCP / OAuth discovery (`openmaskit.oauth.discovery`). The new flow probes the MCP URL, parses the `WWW-Authenticate` challenge for a `resource_metadata` link (RFC 9728), follows it to the protected resource metadata, and reads `authorization_servers[0]` to find the OAuth authorization server. The query string of the protected-resource URL is preserved verbatim, which is required for servers (e.g. Supabase) that scope the resource by a query parameter.
- Host-derived discovery is kept as a fallback for servers that don't advertise `WWW-Authenticate` (GitLab and other early MCP implementations).
- Templated `mcp_host` for marketplace install: catalog entries can declare `meta.params: [{name, label, required, placeholder, description}]`; the install handler validates user-supplied values, URL-encodes them, and appends them as a query string to `mcp_host`. Undeclared param names are rejected so callers can't sneak extra query keys onto the upstream URL.
- DCR catalog entries can now omit `oauth.issuer` — when absent, the install handler runs `discovery.discover(resolved_url)` to find it, with discovered scopes used as defaults when none are selected.
- Install modal: cross-domain trust warning surfaces when the discovered authorization-server apex differs from the MCP URL apex (e.g. a malicious server delegating to an attacker-controlled host).
- Install modal: install-time `Resource:` line shows the canonical resource identifier from protected resource metadata, so users can confirm what they're authorizing.

### Changed
- `oauth/handler.py:FileTokenStorage.discover_oauth_metadata` simplified: its dead protected-resource-metadata path (which was built at the wrong host for cross-host servers and only ever populated unused `scopes_supported`) is removed. Install-time discovery is handled by the new `oauth.discovery` module; runtime discovery only resolves `registration_endpoint` for first-time DCR.
- "Experimental: Dynamic Client Registration may not work with all OAuth providers" banner removed from the custom-server install modal — DCR now works against real spec-compliant servers (Supabase verified end-to-end) and the legacy host-derived fallback covers older ones.

## [0.2.0] - 2026-06-01

### Added
- Static HTTP headers on `UpstreamHttpConfig` for non-OAuth API-key auth (Datadog `DD-API-KEY`, Stripe `Authorization: Bearer`, etc.). Configurable in `openmaskit.yaml`, the Add Server form, and marketplace install modals.
- Catalog `meta.headers` support: marketplace entries can declare HTTP header credentials with the same `{label, description, type, required}` shape as `meta.env`. The header-auth install branch validates required headers and persists them encrypted.
- Reserved-header denylist on the input boundary: transport-layer names (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`), MCP-protocol names (`mcp-protocol-version`, `mcp-session-id`), and any name containing `openmaskit` are rejected at submit-time with a clear error.
- `OPENMASKIT_DISABLE_MARKETPLACE=1` env var to opt out of all backend calls to `api.maskitmcp.com` (catalog browse, server detail, version check). Custom servers continue to work.
- README "Telemetry" section and SECURITY.md "Telemetry" section disclosing the anonymous installation ID (`~/.openmaskit/.installation_id`) and version that travel on marketplace requests, plus the opt-out env var.

### Changed
- `mcp_servers.config` migrated from plaintext JSON to a Fernet-encrypted `config_enc` BLOB. Stored env vars, HTTP headers, and OAuth `client_secret` values are now encrypted at rest using the same key (`~/.openmaskit/.key` or `OPENMASKIT_ENCRYPTION_KEY`) that protects OAuth tokens and the traffic audit log. **The migration runs automatically on first start and is one-way — back up `store.db` before upgrading if you want a rollback path.**
- File-based configuration no longer documents `injections` in `openmaskit.yaml`; manage them through the dashboard instead. No functional change — the feature still works at runtime.

### Fixed
- `_build_upstream_config` silently dropped the `headers` field on the way from the stored config dict to `UpstreamHttpConfig`, so marketplace and custom HTTP installs with static headers landed without auth and 401'd upstream.
- User-selected OAuth scopes on HTTP MCP installs are now honored — the MCP SDK's `get_client_metadata_scopes` was overwriting the operator's choice with PRM `scopes_supported`. Patched via `oauth/sdk_patches.py`.

## [0.1.2] - 2026-06-01

### Changed
- Trimmed distribution artifacts and fixed stale URLs / version references in published metadata.

### Fixed
- Silenced spurious asyncgen-teardown warnings on shutdown.

## [0.1.1] - 2026-06-01

### Added
- Bring-your-own and Dynamic Client Registration OAuth install modes for marketplace servers, with a setup-guide link rendered on the env-var modal.
- Install-type badges (BYO / DCR / BROKER / ENV) on marketplace cards.

### Changed
- Env-var modal polish.

[Unreleased]: https://github.com/MaskitMCP/openmaskit/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/MaskitMCP/openmaskit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/MaskitMCP/openmaskit/releases/tag/v0.1.1
