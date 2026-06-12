"""On-disk credential store, shared with the Ralio CLI.

The layout mirrors the CLI byte-for-byte so :func:`ralio.register` and
``ralio auth agent`` are interchangeable — either one can write the
credentials and the other (or :class:`ralio.RalioClient`) can consume them:

- ``~/.ralio/credentials.json`` (0600) — ``client_id``, ``key_jkt``, tokens.
- ``~/.ralio/keys/<jkt>.pem``   (0600) — the P-256 private key, PKCS8 PEM,
  named by its RFC 7638 thumbprint.

``RALIO_CONFIG_DIR`` overrides ``~/.ralio`` (tests, multi-tenant hosts).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "https://api.ralio.co"

_DIR_MODE = 0o700
_SECRET_FILE_MODE = 0o600


def resolve_base_url(explicit: str | None = None) -> str:
    """Explicit value, else ``RALIO_API_URL``, else production. No trailing slash."""
    return (explicit or _env("RALIO_API_URL") or DEFAULT_BASE_URL).rstrip("/")


def config_dir() -> Path:
    return Path(_env("RALIO_CONFIG_DIR") or Path.home() / ".ralio")


def credentials_path() -> Path:
    return config_dir() / "credentials.json"


def key_path_for(jkt: str) -> Path:
    """Default on-disk location for the key whose RFC 7638 thumbprint is *jkt*."""
    return config_dir() / "keys" / f"{jkt}.pem"


def save_credentials(creds: dict[str, Any]) -> None:
    """Persist *creds* at the CLI-compatible credentials path, mode 0600, atomically."""
    _ensure_secret_dir(config_dir())
    _write_secret_file(credentials_path(), json.dumps(creds, indent=2) + "\n")


def load_credentials() -> dict[str, Any] | None:
    """Load persisted credentials, or ``None`` when absent or unreadable."""
    try:
        raw = credentials_path().read_text()
    except OSError:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def ensure_keys_dir() -> None:
    """Create the keys directory (and config dir) with owner-only permissions."""
    _ensure_secret_dir(config_dir())
    _ensure_secret_dir(config_dir() / "keys")


def delete_private_key(path: str | Path) -> None:
    """Remove a private key file, if present. Idempotent."""
    Path(path).unlink(missing_ok=True)


def _env(name: str) -> str | None:
    """Env var value, with the empty string treated as unset."""
    return os.environ.get(name) or None


def _ensure_secret_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    # mkdir's mode is masked by the umask and skipped for pre-existing dirs.
    with contextlib.suppress(OSError):
        directory.chmod(_DIR_MODE)


def _write_secret_file(path: Path, data: str) -> None:
    """Atomic secret write: temp file chmodded 0600 before any bytes land."""
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with contextlib.suppress(OSError, AttributeError):
            # fchmod unavailable on Windows.
            os.fchmod(tmp_fd, _SECRET_FILE_MODE)
        with os.fdopen(tmp_fd, "w") as f:
            tmp_fd = -1
            f.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
