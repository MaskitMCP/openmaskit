# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

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

OpenMaskit encrypts OAuth tokens and other credentials at rest using Fernet symmetric encryption. The encryption key is derived per-installation and stored at `~/.openmaskit/`. If you believe the key derivation or storage has a weakness, please report it.
