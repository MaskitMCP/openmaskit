"""Helpers shared by HTTP-transport install paths (custom_targets, marketplace).

Currently exposes `clean_http_headers`, the input-side validator for the
`headers` dict that lands in `UpstreamHttpConfig.headers`. The same function
is used by:

- POST /api/targets/custom — user-typed headers from the Add Server form.
- POST /api/marketplace/install — user-typed values for a catalog entry whose
  `meta.headers` declares header-name-keyed credential prompts.
"""

from __future__ import annotations

# Headers a user is never allowed to set as a static upstream header.
#
# Three categories, all enforced case-insensitively:
#
# 1. Transport-layer: httpx (or the underlying HTTP/1.1 layer) computes these
#    from the request body / URL / connection. A user-supplied value is at
#    best ignored, at worst breaks the connection in confusing ways
#    (`Connection: close` silently kills streaming; `Host` derails TLS SNI).
# 2. MCP protocol-layer: the SDK negotiates these per session. Overriding
#    them either fails initialize or hijacks a session id.
#
# `Authorization` is handled separately (only forbidden when OAuth is
# configured; raw-token use against non-OAuth servers is allowed).
_RESERVED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "mcp-protocol-version",
        "mcp-session-id",
    }
)

# Substring (case-insensitive) reserved for future OpenMaskit-injected
# headers — trace propagation, routing, etc. Using a `contains` check rather
# than a prefix because it's tighter to bypass and the overreach surface is
# essentially nil (no legitimate third-party header mentions "openmaskit").
_RESERVED_SUBSTRING = "openmaskit"


def clean_http_headers(raw: object) -> tuple[dict[str, str] | None, str | None]:
    """Normalize a request body 'headers' field into a clean dict.

    - Strip whitespace from keys and values.
    - Drop entries with empty name or empty value (lets the install modal
      submit a partially-filled form without 400ing on the empty rows).
    - Reject CR/LF in either name or value (header-injection guard).
    - Reject duplicate keys after whitespace normalization.
    - Reject reserved transport/MCP-protocol names and any name containing
      "openmaskit" so a misconfiguration fails at submit-time with a clear
      message rather than as a cryptic upstream error days later.

    `Authorization` is allowed here (used by some non-OAuth APIs) and is
    rejected separately by the caller / model when oauth is configured.

    Returns (cleaned_dict, error). cleaned_dict may be {} when nothing was
    supplied; callers decide whether to attach it to the config.
    """
    if raw is None:
        return {}, None
    if not isinstance(raw, dict):
        return None, "headers must be an object of {name: value}"

    cleaned: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None, "header names and values must be strings"
        name = key.strip()
        val = value.strip()
        if not name or not val:
            continue
        if any(ch in name for ch in ("\r", "\n")) or any(ch in val for ch in ("\r", "\n")):
            return None, f"header '{name}' must not contain CR or LF"
        lower = name.lower()
        if lower in _RESERVED_HEADERS:
            return (
                None,
                f"header '{name}' is reserved by the HTTP transport or MCP "
                f"protocol and can't be set manually",
            )
        if _RESERVED_SUBSTRING in lower:
            return (
                None,
                f"header '{name}' contains the reserved 'openmaskit' "
                f"namespace",
            )
        if name in cleaned:
            return None, f"duplicate header '{name}'"
        cleaned[name] = val
    return cleaned, None
