"""Encrypted-at-rest storage for device passwords used by scheduled scans.

Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The key comes
from, in order:

1. ``ROUTER_SECURITY_SECRET_KEY`` — a Fernet key (``Fernet.generate_key()``).
   Recommended: keep it outside the data directory, e.g. in a secrets manager
   or the container environment, so a copied database alone is useless.
2. A key file (``ROUTER_SECURITY_SECRET_KEY_FILE``, default ``secret.key``
   next to the history database), created on first use with mode 0600.

Changing or losing the key makes stored passwords undecryptable; the schedule
then reports a credential error and the password must be re-entered.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class CredentialError(Exception):
    pass


def _history_dir() -> Path:
    history = os.environ.get("ROUTER_SECURITY_DB")
    if history:
        return Path(history).parent
    return Path(__file__).parent.parent.parent / "data"


def default_key_file() -> Path:
    explicit = os.environ.get("ROUTER_SECURITY_SECRET_KEY_FILE")
    return Path(explicit) if explicit else _history_dir() / "secret.key"


def _load_or_create_key_file(path: Path) -> bytes:
    try:
        return path.read_bytes().strip()
    except FileNotFoundError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    try:
        # O_EXCL: if another process created it first, use theirs.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes().strip()
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    logger.warning(
        "Created credential key file %s. Back it up; set ROUTER_SECURITY_SECRET_KEY to keep the key "
        "outside the data directory.",
        path,
    )
    return key


class CredentialVault:
    def __init__(self, key: Optional[bytes] = None, key_file: Optional[Path] = None):
        if key is None:
            env_key = os.environ.get("ROUTER_SECURITY_SECRET_KEY")
            if env_key:
                key = env_key.strip().encode()
                self.key_source = "env"
            else:
                key = _load_or_create_key_file(Path(key_file) if key_file else default_key_file())
                self.key_source = "file"
        else:
            self.key_source = "explicit"
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as e:
            raise CredentialError(
                "Invalid credential key: ROUTER_SECURITY_SECRET_KEY must be a Fernet key "
                "(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
            ) from e

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except (InvalidToken, ValueError, AttributeError) as e:
            raise CredentialError(
                "Stored password can't be decrypted (the credential key changed); re-enter the password"
            ) from e
