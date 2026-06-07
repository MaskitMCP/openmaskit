"""Config storage serde — the transform between in-memory and on-disk shapes.

On-disk shape (``mcp_servers.config_json``) is plaintext JSON whose secret values
are inline-encrypted as ``{"enc": "ENCRYPTED:..."}`` Fernet ciphertext. ``env``
and ``headers`` entries are always wrapped as ``{"value": ..., "type": ...}`` so
that the redactor (for API display) and the FE form renderer can tell secrets
from plaintext. ``oauth.client_secret`` and ``oauth.registration_token`` are
always secret — no type marker needed.

Four boundary functions:

- ``dump_config(structured) -> str`` — for writes. Encrypts secrets inline.
- ``load_runtime_config(json) -> dict`` — for ``proxy/upstream.py`` and OAuth
  flows. Decrypts every secret and flattens ``env``/``headers`` to
  ``{KEY: VALUE_STRING}`` so runtime code sees the simple shape it already
  expects.
- ``load_display_config(json) -> dict`` — for API responses. Replaces every
  secret with ``"••••••••"`` without ever touching the encryption key.
- ``merge_update(stored_json, incoming) -> dict`` — for edit-modal updates.
  Implements the "leave blank to keep existing" pattern: incoming entries that
  omit a secret value (or send the redaction sentinel) keep the encrypted
  stored value.

The dump path tolerates both already-encrypted ``{"enc": ...}`` values (used by
``merge_update`` to preserve unchanged secrets) and plaintext strings (from
freshly-typed user input).
"""

from __future__ import annotations

import json
from typing import Any

from openmaskit.security import TokenEncryption

# Valid type values for env / header entries. Only ``secret`` triggers
# encryption; the rest are stored plaintext and shown directly in the UI.
VALID_TYPES = {"text", "secret", "path", "number"}
SECRET_TYPES = {"secret"}

# What we show in place of a secret when serving the API. Picked to be
# visually distinct from any real value and recognisable on the FE so
# incoming updates can be matched against it for the preserve-secret merge.
REDACTED_SENTINEL = "••••••••"

# OAuth fields that are always treated as secret regardless of input shape.
_OAUTH_SECRET_FIELDS = ("client_secret", "registration_token")


def _encrypt(plaintext: str) -> dict[str, str]:
    return {"enc": TokenEncryption().encrypt(plaintext)}


def _decrypt(enc_obj: dict[str, str]) -> str:
    return TokenEncryption().decrypt(enc_obj["enc"])


def _is_enc(v: Any) -> bool:
    """True if ``v`` is the inline-encrypted ``{"enc": "..."}`` wrapper."""
    return isinstance(v, dict) and set(v.keys()) == {"enc"} and isinstance(v["enc"], str)


def _normalize_entry(value: Any, *, default_type: str = "secret") -> dict[str, Any]:
    """Coerce a raw env/header entry into the ``{value, type}`` shape.

    Accepts:
    - already-structured ``{"value": ..., "type": ...}`` — passed through with
      type validation.
    - bare scalar — wrapped with ``default_type`` (conservative: assume secret).
    """
    if isinstance(value, dict) and "value" in value and "type" in value:
        if value["type"] not in VALID_TYPES:
            raise ValueError(
                f"Invalid env/header type {value['type']!r}; "
                f"valid types: {sorted(VALID_TYPES)}"
            )
        return {"value": value["value"], "type": value["type"]}
    return {"value": value, "type": default_type}


# ---------- dump (in-memory → on-disk JSON) ----------


def dump_config(config: dict) -> str:
    """Encrypt secrets inline, return JSON string for storage in ``config_json``.

    ``config`` is the structured shape: top-level keys plus ``oauth``, ``env``,
    ``headers`` (the last two may use ``{value, type}`` wrappers or bare
    scalars — bare scalars default to type=secret).
    """
    out: dict[str, Any] = {}
    for k, v in config.items():
        if k == "oauth":
            out[k] = _dump_oauth(v) if isinstance(v, dict) else v
        elif k in ("env", "headers"):
            wrapped = _dump_typed_map(v)
            if wrapped:
                out[k] = wrapped
        else:
            out[k] = v
    return json.dumps(out, separators=(",", ":"))


def _dump_oauth(oauth: dict) -> dict:
    out = dict(oauth)
    for field in _OAUTH_SECRET_FIELDS:
        v = out.get(field)
        if v is None or v == "":
            # Don't carry empty secret fields into storage.
            out.pop(field, None)
            continue
        if _is_enc(v):
            # Already encrypted (preserved by merge_update); keep as-is.
            continue
        if isinstance(v, str):
            out[field] = _encrypt(v)
    return out


def _dump_typed_map(raw: dict | None) -> dict:
    if not raw:
        return {}
    out: dict[str, dict] = {}
    for k, v in raw.items():
        entry = _normalize_entry(v)
        value = entry["value"]
        if entry["type"] in SECRET_TYPES and isinstance(value, str) and value != "":
            value = _encrypt(value)
        # _is_enc(value) means the merge preserved an encrypted stored value;
        # keep as-is.
        out[k] = {"value": value, "type": entry["type"]}
    return out


# ---------- load for runtime (decrypted + flattened) ----------


def load_runtime_config(config_json: str) -> dict:
    """Decrypt all secrets, flatten ``env``/``headers`` to ``{KEY: VALUE_STRING}``.

    This is the shape that ``proxy/upstream.py`` and the OAuth flows already
    consume. The serde lives at this single boundary so the rest of the
    runtime stays unchanged.
    """
    parsed = json.loads(config_json)
    out: dict[str, Any] = {}
    for k, v in parsed.items():
        if k == "oauth" and isinstance(v, dict):
            out[k] = _load_runtime_oauth(v)
        elif k in ("env", "headers"):
            flat = _flatten_typed_map(v)
            if flat:
                out[k] = flat
        else:
            out[k] = v
    return out


def _load_runtime_oauth(oauth: dict) -> dict:
    out = dict(oauth)
    for field in _OAUTH_SECRET_FIELDS:
        v = out.get(field)
        if _is_enc(v):
            out[field] = _decrypt(v)
    return out


def _flatten_typed_map(raw: dict | None) -> dict:
    if not raw:
        return {}
    out: dict[str, Any] = {}
    for k, entry in raw.items():
        # Tolerate already-flat shapes (defensive — shouldn't happen for new
        # writes, but a free-form import / hand-edited row could land here).
        if not isinstance(entry, dict) or "value" not in entry:
            out[k] = entry
            continue
        value = entry["value"]
        if _is_enc(value):
            value = _decrypt(value)
        out[k] = value
    return out


# ---------- load for display (typed shape, secrets redacted) ----------


def load_display_config(config_json: str) -> dict:
    """Parse the stored shape; replace secrets with a sentinel; keep types.

    Never touches the encryption key — safe even when Fernet would fail or
    when a malicious caller reaches the endpoint.
    """
    parsed = json.loads(config_json)
    out: dict[str, Any] = {}
    for k, v in parsed.items():
        if k == "oauth" and isinstance(v, dict):
            out[k] = _redact_oauth(v)
        elif k in ("env", "headers"):
            red = _redact_typed_map(v)
            if red:
                out[k] = red
        else:
            out[k] = v
    return out


def _redact_oauth(oauth: dict) -> dict:
    out = dict(oauth)
    for field in _OAUTH_SECRET_FIELDS:
        if field in out and out[field] is not None and out[field] != "":
            out[field] = REDACTED_SENTINEL
    return out


def _redact_typed_map(raw: dict | None) -> dict:
    if not raw:
        return {}
    out: dict[str, dict] = {}
    for k, entry in raw.items():
        if not isinstance(entry, dict) or "value" not in entry:
            # Unknown legacy shape — redact to be safe.
            out[k] = {"value": REDACTED_SENTINEL, "type": "secret"}
            continue
        type_ = entry.get("type", "secret")
        value = entry["value"]
        if type_ in SECRET_TYPES or _is_enc(value):
            display = REDACTED_SENTINEL
        else:
            display = value
        out[k] = {"value": display, "type": type_}
    return out


# ---------- merge update (preserve secrets on absence/redaction) ----------


def merge_update(stored_json: str, incoming: dict) -> dict:
    """Merge an incoming structured update into the stored config.

    The result is *unwritten* — pass it through ``dump_config`` to persist.

    Rule: incoming entries that omit a secret value, send empty string, or send
    the redaction sentinel keep the stored (encrypted) value. Real values in
    incoming overwrite. Non-secret entries are replaced verbatim.

    For ``env`` / ``headers``, this is per-key: an incoming map replaces the
    stored map key-for-key, but a secret entry whose incoming value is blank
    or sentinel keeps the stored encrypted value.
    """
    stored = json.loads(stored_json)
    out: dict[str, Any] = {}

    # Top-level fields: incoming wins; missing keys keep stored.
    keys = set(stored.keys()) | set(incoming.keys())
    for k in keys:
        if k in ("oauth", "env", "headers"):
            continue  # handled below
        if k in incoming:
            out[k] = incoming[k]
        else:
            out[k] = stored[k]

    # OAuth
    if "oauth" in incoming or "oauth" in stored:
        merged = _merge_oauth(stored.get("oauth", {}), incoming.get("oauth", {}))
        if merged:
            out["oauth"] = merged

    # env / headers
    for k in ("env", "headers"):
        if k in incoming or k in stored:
            merged = _merge_typed_map(stored.get(k, {}), incoming.get(k, {}))
            if merged:
                out[k] = merged

    return out


def _is_blank_or_sentinel(v: Any) -> bool:
    return v is None or v == "" or v == REDACTED_SENTINEL


def _merge_oauth(stored: dict, incoming: dict) -> dict:
    out = dict(stored)
    for k, v in incoming.items():
        if k in _OAUTH_SECRET_FIELDS and _is_blank_or_sentinel(v):
            # Keep stored (still encrypted).
            continue
        out[k] = v
    return out


def _merge_typed_map(stored: dict, incoming: dict) -> dict:
    out = dict(stored)
    for k, raw in incoming.items():
        entry = _normalize_entry(raw)
        if entry["type"] in SECRET_TYPES and _is_blank_or_sentinel(entry["value"]):
            # Blank/sentinel for a secret on update = preserve stored entry.
            continue
        out[k] = entry
    return out
