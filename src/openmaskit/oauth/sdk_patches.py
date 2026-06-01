"""Patch the MCP SDK's scope-selection strategy to honour user-supplied scopes.

The MCP authorization spec mandates that clients select scopes from either the
WWW-Authenticate `scope` parameter or the protected-resource metadata's
`scopes_supported` array, in that order — never from caller-supplied client
metadata. The SDK implements this faithfully in
`mcp.client.auth.utils.get_client_metadata_scopes`, which means any scope the
operator chose in OpenMaskit's install UI is overwritten by whatever the upstream
MCP server advertises.

For most servers that's reasonable. For BYO installs against providers whose
PRM lists scopes the operator's own OAuth client cannot grant (e.g. Atlassian's
Remote MCP advertising `read:all:twg`, only obtainable by Atlassian-internal
clients), spec-compliant selection makes the install unauthorisable.

This module hot-patches the SDK so that when an explicit scope override has
been registered for a given OAuthClientMetadata instance, the patched function
returns it verbatim instead of consulting PRM. When no override is registered,
spec behaviour is preserved.
"""

from __future__ import annotations

import logging
import sys

from mcp.client.auth import oauth2 as _sdk_oauth2
from mcp.shared.auth import OAuthClientMetadata

logger = logging.getLogger(__name__)


# Keyed by id(OAuthClientMetadata). The provider holds its client_metadata for
# its lifetime so the id stays stable; entries are released explicitly when a
# target is removed via `release_scope_override`.
_overrides: dict[int, str] = {}


def register_scope_override(client_metadata: OAuthClientMetadata, scope: str | None) -> None:
    """Pin a user-selected scope string to a client_metadata instance.

    The patched scope-selection function returns this scope instead of the
    PRM-advertised scopes_supported. Empty or None scopes are ignored (spec
    behaviour is used).
    """
    if scope and scope.strip():
        _overrides[id(client_metadata)] = scope


def release_scope_override(client_metadata: OAuthClientMetadata) -> None:
    """Drop a previously-registered override. Safe to call if none exists."""
    _overrides.pop(id(client_metadata), None)


def _patched_get_scopes(www_auth_scope, prm_metadata, as_metadata=None):
    # The SDK invokes this from a coroutine method as
    #   self.context.client_metadata.scope = get_client_metadata_scopes(...)
    # so the caller's frame exposes `self`, from which we reach the registered
    # client_metadata. Frame inspection is best-effort; on any surprise we fall
    # through to the SDK's original spec-compliant behaviour.
    try:
        caller_frame = sys._getframe(1)
        caller_self = caller_frame.f_locals.get("self")
        if caller_self is not None:
            context = getattr(caller_self, "context", None)
            client_metadata = getattr(context, "client_metadata", None)
            if client_metadata is not None:
                override = _overrides.get(id(client_metadata))
                if override:
                    return override
    except Exception:
        logger.debug("scope override lookup failed; using spec behaviour", exc_info=True)

    return _original_get_scopes(www_auth_scope, prm_metadata, as_metadata)


_original_get_scopes = _sdk_oauth2.get_client_metadata_scopes


def install() -> None:
    """Apply the patch. Idempotent."""
    current = _sdk_oauth2.get_client_metadata_scopes
    if getattr(current, "_openmaskit_patched", False):
        return
    _patched_get_scopes._openmaskit_patched = True  # type: ignore[attr-defined]
    _sdk_oauth2.get_client_metadata_scopes = _patched_get_scopes
    logger.debug("Patched mcp.client.auth.oauth2.get_client_metadata_scopes")


install()
