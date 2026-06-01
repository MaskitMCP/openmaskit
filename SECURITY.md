# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Scope

OpenMaskit runs locally on a user's own machine. The following are **in scope**:

- Cross-origin attacks from a webpage in the user's browser against the localhost dashboard / MCP endpoint
- OAuth callback integrity (state forgery, code injection)
- A malicious or compromised upstream MCP server crashing, corrupting, or exfiltrating data via the proxy
- Mask/unmask correctness bugs (alias collisions, races, leaks of unmasked values in places they shouldn't appear)

The following are **out of scope** for this project's threat model:

- Other local users on the same machine reading files in `~/.openmaskit/`
- An attacker who already has shell access as the OpenMaskit-running user
- Loss or theft of the encryption key file (treat it like any other secret)

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing **security@maskitmcp.com**.

Include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or detailed instructions)
- Affected version(s)
- Any suggested mitigations you are aware of

### What to expect

- **Acknowledgement** within 2 business days
- **Status update** (confirmed, not reproducible, or fix in progress) within 7 days
- We will coordinate a disclosure timeline with you before publishing a fix

We ask that you give us reasonable time to address the issue before any public disclosure.

## Encryption of stored credentials

OpenMaskit encrypts the following at rest using Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256):

- OAuth tokens for installed servers (`~/.openmaskit/oauth/{handle}.json`)
- The traffic audit log (`~/.openmaskit/traffic.db` — unmasked args and responses)
- Stored server configurations including env vars, HTTP headers, and OAuth `client_secret` values (`mcp_servers.config_enc` column in `~/.openmaskit/store.db`)

The encryption key is generated on first start and stored at `~/.openmaskit/.key` (mode `0600`). It can be overridden by setting `OPENMASKIT_ENCRYPTION_KEY`. If you believe the key generation, storage, or scope of encrypted data has a weakness, please report it.
