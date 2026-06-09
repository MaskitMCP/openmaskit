# Changelog

All notable changes to OpenMaskit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1] - 2026-06-09

### Added
- `POST /api/marketplace/{target_id}/delete` permanently removes an installed marketplace server: disconnects via `TargetManager`, deletes the OAuth token file at `{store_dir}/oauth/{handle}.json` (tokens and `client_info`), and drops the row from `mcp_servers`. The Servers page Delete button uses it for marketplace cards.
- Sticky in-page nav (Try it out / Masking / Guardrails / Injections) on the tool detail page with a center-distance scroll-spy, replacing the static Back-to-Tools link.
- Traffic detail blurs unmasked args and the upstream response behind a Show toggle so glanceable inspection doesn't leak secrets. Aliases inside masked args / response render as clickable links that jump to the matching Mappings row.
- E2E test scaffold (`tests/e2e`) with a Postgres flow. Skipped in the default `pytest tests/` run.

### Changed
- Servers cards: the whole card is now the click target into the tool list (previously only the inner title block). Buttons stay visible by default with text labels (Connect / Deactivate / Delete / Re-authorize / Edit) and uniform card hover. Deactivate picks up an orange hover treatment.

### Fixed
- Tutorial overlay no longer parks the popover on top of the highlighted component. Placement now measures the popover and falls back through preferred → opposite → side → scroll-and-corner-pin. Section selectors switched from text-`:contains()` (which mis-matched because Try It Out contained the word "Masking") to stable element IDs.
- "Add Masking Rule" modal no longer carries stale state from the previous open.
- Masking rules now reload from the store when a target is hot-added, so newly installed servers see existing rules immediately instead of after a restart.
- Dashboard console errors (null `tags` on marketplace cards, null `editingRule` / `editingMapper` on tool detail) and the clipped Show button in the Mappings table.

## [0.6.0] - 2026-06-07

### Changed
- **Breaking: `mcp_servers` table reshape.** Drops the whole-blob Fernet `config_enc` column in favour of a plaintext `config_json` whose secret values are inline-encrypted as `{"enc": "ENCRYPTED:..."}` Fernet ciphertext. Adds `source` (`marketplace` | `custom`) and `backend_id` columns so the install origin is a fact on the row, not a heuristic on the config dict. Existing `~/.openmaskit/store.db` files from 0.5.0 or earlier won't load — remove and reinstall affected servers.
- `env` and `headers` entries persist as `{value, type}` wrappers (`text` / `secret` / `path` / `number`). Only secret-typed values are encrypted on disk; the rest stay plaintext and inspectable.
- Custom-target API routes (`GET/POST /api/targets/custom/{id}*`) now 403 marketplace-source rows synchronously, before any DB write or connect attempt. Marketplace rows are managed through `/api/marketplace/*` only.
- BYO and DCR marketplace installs now correctly stamp `source="marketplace"` and `backend_id` on the row — previously they were indistinguishable from hand-rolled custom targets, which let the dashboard Edit button mutate them.
- API responses redact `oauth.client_secret`, `oauth.registration_token`, and `env`/`header` secret values to `••••••••`. The Edit modal pre-fills password inputs empty with a leave-blank-to-keep-existing contract; `update_server` merges new values into stored on the backend.

### Fixed
- The Servers page's Re-authorize button was never rendering because the template read `target.config.oauth` on a JSON string. `target.config` is now a dict end-to-end.

### Removed
- The Server Configuration ("eye" icon) view-details modal on inactive cards. The Edit modal already covers the same info in a labeled, secrets-safe form.

## [0.5.0] - 2026-06-06

### Changed
- OAuth install and reauthorize now redirect the dashboard tab to the authorization server (same-tab navigation) instead of spawning a new window via `webbrowser.open`. The local OAuth callback runs at `:9473/oauth/callback/{handle}` and finishes the install on the redirect back. Fixes tab stacking, makes the flow work in headless Docker, and respects the browser the user is actually running the dashboard in.
- User-pinned OAuth scope is now defended by a `PinnedScopeClientMetadata` subclass that rejects writes to `scope` instead of the previous `sys._getframe`-based monkey patch of `mcp.client.auth.oauth2.get_client_metadata_scopes`. Same behaviour (operator's scope choice wins over PRM `scopes_supported`), no frame inspection, no upstream-module patching.

### Removed
- Dedicated OAuth callback listener on port `3131`. The `oauth_port` config field, `-o/--oauth-port` CLI flag, and the corresponding Docker port mapping are gone. Update Docker invocations to drop `-p 3131:3131`.
- `openmaskit.oauth.sdk_patches` module. Replaced by `PinnedScopeClientMetadata` in `openmaskit.oauth.handler`.

## [0.4.1] - 2026-06-06

### Added
- Pre-install runtime check: the marketplace install modal now shows the command line that will run plus a `/api/install/check` runtime-presence badge — `✓ detected` (with path), `⚠ not on PATH` (with an install hint), or `podman (substituted for docker)` via the existing container-runtime detection. The modal also opens for bare catalog entries (server-memory etc.) that previously installed in one click, so every install confirms what runs locally.
- RFC 6750 §3 `WWW-Authenticate` `scope` parsing, with RFC 6749 §3.3 token-grammar enforcement. OAuth discovery now combines protected-resource-metadata `scopes_supported` and the resource server's required scopes into a unified `scopes: [{scope, required}]` list; the install modal renders required scopes as locked-checked.
- BYO scope discovery fallback: when a catalog entry omits `available_scopes`, the BYO install modal runs live discovery against the resolved MCP URL so the user still sees a scope picker.

### Changed
- `/api/oauth/discover` returns a single `scopes` field of `{scope, required}` objects instead of separate `scopes_supported` and `scopes_required` arrays. Marketplace install modal frontend updated to match.

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

[Unreleased]: https://github.com/MaskitMCP/openmaskit/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/MaskitMCP/openmaskit/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/MaskitMCP/openmaskit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/MaskitMCP/openmaskit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/MaskitMCP/openmaskit/releases/tag/v0.1.1
