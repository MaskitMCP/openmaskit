"""Security utilities for Maskit: validation and encryption."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def validate_server_id(server_id: str) -> str:
    """Validate server ID for safe filesystem operations.

    Args:
        server_id: Server identifier to validate

    Returns:
        The validated server_id

    Raises:
        ValueError: If server_id contains invalid characters or is too long

    Examples:
        >>> validate_server_id("postgres-prod")
        'postgres-prod'
        >>> validate_server_id("../etc/passwd")
        Traceback (most recent call last):
        ...
        ValueError: Invalid server ID '../etc/passwd': must be 1-64 characters, lowercase alphanumeric, hyphens and underscores only
    """
    if not re.match(r'^[a-z0-9_-]{1,64}$', server_id):
        raise ValueError(
            f"Invalid server ID '{server_id}': must be 1-64 characters, "
            "lowercase alphanumeric, hyphens and underscores only"
        )
    return server_id


class TokenEncryption:
    """Handle encryption/decryption of OAuth token files using Fernet."""

    _KEY_PATH = Path("~/.maskit/.key").expanduser()
    _MAGIC_PREFIX = "ENCRYPTED:"

    def __init__(self):
        self._fernet = None

    def _load_key(self) -> bytes:
        """Load or generate encryption key.

        Priority:
        1. MASKIT_ENCRYPTION_KEY environment variable
        2. ~/.maskit/.key file
        3. Generate new key
        """
        # Check env var first
        env_key = os.environ.get("MASKIT_ENCRYPTION_KEY")
        if env_key:
            logger.debug("Using encryption key from MASKIT_ENCRYPTION_KEY")
            return env_key.encode()

        # Load from file
        if self._KEY_PATH.exists():
            logger.debug(f"Loaded encryption key from {self._KEY_PATH}")
            return self._KEY_PATH.read_bytes().strip()

        # Generate new key
        key = Fernet.generate_key()
        self._KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._KEY_PATH.write_bytes(key)
        self._KEY_PATH.chmod(0o600)
        logger.info(f"Generated new encryption key at {self._KEY_PATH}")
        return key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt JSON string and add magic prefix."""
        if self._fernet is None:
            self._fernet = Fernet(self._load_key())

        encrypted = self._fernet.encrypt(plaintext.encode())
        return self._MAGIC_PREFIX + encrypted.decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt JSON string.

        Returns plaintext as-is if no magic prefix (for migration).
        """
        if not ciphertext.startswith(self._MAGIC_PREFIX):
            # Plaintext token - return for migration
            logger.debug("Detected plaintext token file")
            return ciphertext

        if self._fernet is None:
            self._fernet = Fernet(self._load_key())

        encrypted_data = ciphertext[len(self._MAGIC_PREFIX):].encode()
        return self._fernet.decrypt(encrypted_data).decode()


def read_token_file(path: Path) -> dict:
    """Read and decrypt token file with auto-migration."""
    encryption = TokenEncryption()
    if not path.exists():
        return {}

    try:
        ciphertext = path.read_text()
        plaintext = encryption.decrypt(ciphertext)
        data = json.loads(plaintext)

        # Auto-migrate plaintext tokens
        if not ciphertext.startswith("ENCRYPTED:"):
            logger.info(f"Migrating plaintext token to encrypted: {path}")
            write_token_file(path, data)

        return data
    except Exception as e:
        logger.warning(f"Failed to read token file {path}: {e}")
        return {}


def write_token_file(path: Path, data: dict) -> None:
    """Encrypt and write token file."""
    encryption = TokenEncryption()
    plaintext = json.dumps(data, indent=2)
    ciphertext = encryption.encrypt(plaintext)
    path.write_text(ciphertext)
    path.chmod(0o600)
