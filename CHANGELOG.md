# Changelog

All notable changes to OpenMaskit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-01

### Added
- Static HTTP headers on `UpstreamHttpConfig` for non-OAuth API-key auth (Datadog `DD-API-KEY`, Stripe `Authorization: Bearer`, etc.). Configurable in `openmaskit.yaml`, the Add Server form, and marketplace install modals.
- Catalog `meta.headers` support: marketplace entries can declare HTTP header credentials with the same `{label, description, type, required}` shape as `meta.env`. The header-auth install branch validates required headers and persists them encrypted.
- Reserved-header denylist on the input boundary: transport-layer names (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`), MCP-protocol names (`mcp-protocol-version`, `mcp-session-id`), and any name containing `openmaskit` are rejected at submit-time with a clear error.

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

[Unreleased]: https://github.com/MaskitMCP/openmaskit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/MaskitMCP/openmaskit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/MaskitMCP/openmaskit/releases/tag/v0.1.1
