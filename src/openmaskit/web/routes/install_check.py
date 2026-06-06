"""Pre-install runtime check.

Answers a single question: is the command the user is about to install actually
available on this machine? Frontend already has the catalog data (transport,
URL, args, env names) — this endpoint only returns what the frontend can't
compute itself: PATH presence, container-runtime substitution, and an install
hint when the binary is missing.

Scope: handles `uvx`, `npx`, and `docker` for now. Other commands are answered
honestly (`shutil.which` result) with no install hint attached.
"""

from __future__ import annotations

import logging
import shutil

from starlette.requests import Request
from starlette.responses import JSONResponse

from openmaskit.container import detect_container_runtime

logger = logging.getLogger(__name__)


_INSTALL_HINTS: dict[str, str] = {
    "uvx": "https://docs.astral.sh/uv/getting-started/installation/",
    "npx": "https://nodejs.org/en/download",
    "docker": "https://docs.docker.com/get-docker/",
}


async def install_check(request: Request):
    """POST /api/install/check
    Body: {"command": "<bin name>"}

    Response shape:
      {"present": true,  "resolved_command": "<bin>", "resolved_path": "<path>"}
      {"present": false, "install_hint": "<url>" | null}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)

    command = (body.get("command") or "").strip() if isinstance(body, dict) else ""
    if not command:
        return JSONResponse({"error": "command is required"}, status_code=400)

    # Special-case docker: container.py already owns substitution policy for
    # docker → podman/nerdctl/finch. Defer to it instead of re-implementing.
    if command == "docker":
        runtime = detect_container_runtime()
        if runtime is None:
            return JSONResponse(
                {"present": False, "install_hint": _INSTALL_HINTS.get("docker")}
            )
        return JSONResponse(
            {
                "present": True,
                "resolved_command": runtime,
                "resolved_path": shutil.which(runtime),
            }
        )

    path = shutil.which(command)
    if path:
        return JSONResponse(
            {"present": True, "resolved_command": command, "resolved_path": path}
        )

    return JSONResponse(
        {"present": False, "install_hint": _INSTALL_HINTS.get(command)}
    )
