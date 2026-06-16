"""Credential storage abstractions for the Ralio machine-auth path.

The SDK needs two kinds of credential material:

- stable machine identity: ``client_id`` plus the private key/JWK;
- rotating refresh-token state for this SDK instance's current token family.

Custom stores can source the stable identity from a secret manager, database,
environment variables, or mounted volume while keeping refresh tokens
instance-local or separately keyed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto, _store


@dataclass(frozen=True)
class StoredCredentials:
    """Credentials loaded from or saved to a :class:`CredentialStore`.

    Provide one private-key form: ``private_key``, ``private_key_pem``,
    ``private_jwk``, or ``private_key_path``. ``refresh_token`` is the current
    token for this SDK instance's refresh-token family, not necessarily a
    credential-wide shared value.
    """

    client_id: str
    private_key: EllipticCurvePrivateKey | None = None
    private_key_path: str | Path | None = None
    private_key_pem: str | bytes | None = None
    private_jwk: Mapping[str, str] | None = None
    public_jwk: Mapping[str, str] | None = None
    key_jkt: str | None = None
    refresh_token: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


class CredentialStore(Protocol):
    """Small interface for pluggable Ralio credential storage."""

    def load_credentials(self) -> StoredCredentials | None:
        """Return credentials for this SDK instance, or ``None`` if absent."""
        ...

    def save_credentials(self, credentials: StoredCredentials) -> None:
        """Persist stable identity material and any initial refresh token."""
        ...

    def save_refresh_token(self, refresh_token: str) -> None:
        """Persist the latest refresh token for this SDK instance."""
        ...


class LocalCredentialStore:
    """CLI-compatible local credential store.

    Stable identity is read from and written to ``credentials.json`` under the
    Ralio config directory. Refresh tokens are instance-local by default:
    without ``refresh_token_slot`` or ``refresh_token_path`` they are kept only
    in this store object, avoiding accidental sharing between concurrent SDK
    clients. Pass a distinct slot/path per worker to persist each worker's
    refresh-token family across restarts.
    """

    def __init__(
        self,
        *,
        config_dir: str | Path | None = None,
        refresh_token_slot: str | None = None,
        refresh_token_path: str | Path | None = None,
        use_legacy_shared_refresh_token: bool = False,
    ) -> None:
        if refresh_token_slot and refresh_token_path:
            raise ValueError("pass either refresh_token_slot or refresh_token_path, not both")
        self._config_dir = Path(config_dir) if config_dir is not None else _store.config_dir()
        self._credentials_path = self._config_dir / "credentials.json"
        self._refresh_token_path = self._resolve_refresh_token_path(
            refresh_token_slot, refresh_token_path
        )
        self._use_legacy_shared_refresh_token = use_legacy_shared_refresh_token
        self._memory_refresh_token: str | None = None

    @property
    def credentials_path(self) -> Path:
        """Path to the CLI-compatible ``credentials.json`` file."""
        return self._credentials_path

    def key_path_for(self, jkt: str) -> Path:
        """Default on-disk location for a private key with thumbprint *jkt*."""
        return self._config_dir / "keys" / f"{jkt}.pem"

    def ensure_keys_dir(self) -> None:
        """Create the local keys directory with owner-only permissions."""
        _store._ensure_secret_dir(self._config_dir)
        _store._ensure_secret_dir(self._config_dir / "keys")

    def load_credentials(self) -> StoredCredentials | None:
        raw = self._read_credentials_file()
        if raw is None:
            return None

        client_id = raw.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            return None

        key_path = raw.get("key_path")
        key_jkt = raw.get("key_jkt")
        private_key_path: Path | None = None
        if isinstance(key_path, str) and key_path:
            private_key_path = Path(key_path)
        elif isinstance(key_jkt, str) and key_jkt:
            private_key_path = self.key_path_for(key_jkt)

        public_jwk = _string_mapping(raw.get("public_jwk"))
        refresh_token = self._load_refresh_token()
        if refresh_token is None and self._use_legacy_shared_refresh_token:
            legacy_refresh_token = raw.get("refresh_token")
            if isinstance(legacy_refresh_token, str) and legacy_refresh_token:
                refresh_token = legacy_refresh_token

        known_keys = {
            "client_id",
            "key_path",
            "key_jkt",
            "public_jwk",
            "refresh_token",
        }
        return StoredCredentials(
            client_id=client_id,
            private_key_path=private_key_path,
            public_jwk=public_jwk,
            key_jkt=key_jkt if isinstance(key_jkt, str) and key_jkt else None,
            refresh_token=refresh_token,
            extra={key: value for key, value in raw.items() if key not in known_keys},
        )

    def save_credentials(self, credentials: StoredCredentials) -> None:
        private_key = _private_key_from_credentials(credentials)
        key_path = Path(credentials.private_key_path) if credentials.private_key_path else None
        public_jwk = _string_mapping(credentials.public_jwk)
        key_jkt = credentials.key_jkt

        if private_key is not None:
            public_jwk = _crypto.public_jwk(private_key)
            key_jkt = key_jkt or _crypto.jwk_thumbprint(public_jwk)
            if key_path is None:
                key_path = self.key_path_for(key_jkt)
            _crypto.save_private_key(key_path, private_key)
        elif key_jkt is None and public_jwk is not None:
            key_jkt = _crypto.jwk_thumbprint(public_jwk)
        elif key_path is None and key_jkt:
            key_path = self.key_path_for(key_jkt)

        payload = dict(credentials.extra)
        payload["client_id"] = credentials.client_id
        payload.setdefault("auth_method", "private_key_jwt")
        if key_jkt:
            payload["key_jkt"] = key_jkt
        if key_path is not None:
            payload["key_path"] = str(key_path)
        if credentials.refresh_token:
            payload["refresh_token"] = credentials.refresh_token

        _store._ensure_secret_dir(self._config_dir)
        _write_json_secret(self._credentials_path, payload)
        if credentials.refresh_token:
            self.save_refresh_token(credentials.refresh_token)

    def save_refresh_token(self, refresh_token: str) -> None:
        self._memory_refresh_token = refresh_token
        if self._refresh_token_path is not None:
            _store._ensure_secret_dir(self._refresh_token_path.parent)
            _write_json_secret(self._refresh_token_path, {"refresh_token": refresh_token})
        if self._use_legacy_shared_refresh_token:
            raw = self._read_credentials_file() or {}
            raw["refresh_token"] = refresh_token
            _store._ensure_secret_dir(self._config_dir)
            _write_json_secret(self._credentials_path, raw)

    def _resolve_refresh_token_path(
        self,
        refresh_token_slot: str | None,
        refresh_token_path: str | Path | None,
    ) -> Path | None:
        if refresh_token_path is not None:
            return Path(refresh_token_path)
        if refresh_token_slot is None:
            return None
        return self._config_dir / "refresh-tokens" / f"{_safe_slot(refresh_token_slot)}.json"

    def _read_credentials_file(self) -> dict[str, Any] | None:
        return _read_json_object(self._credentials_path)

    def _load_refresh_token(self) -> str | None:
        if self._memory_refresh_token:
            return self._memory_refresh_token
        if self._refresh_token_path is None:
            return None
        raw = _read_json_object(self._refresh_token_path)
        if raw is None:
            return None
        refresh_token = raw.get("refresh_token")
        return refresh_token if isinstance(refresh_token, str) and refresh_token else None


def _private_key_from_credentials(
    credentials: StoredCredentials,
) -> EllipticCurvePrivateKey | None:
    if credentials.private_key is not None:
        return credentials.private_key
    if credentials.private_key_pem is not None:
        return _crypto.load_private_key_pem(credentials.private_key_pem)
    if credentials.private_jwk is not None:
        return _crypto.load_private_key_jwk(credentials.private_jwk)
    return None


def _read_json_object(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text()
    except OSError:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_json_secret(path: Path, data: Mapping[str, Any]) -> None:
    _store._write_secret_file(path, json.dumps(data, indent=2) + "\n")


def _string_mapping(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            return None
        result[key] = item
    return result


def _safe_slot(slot: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in slot)
    if not cleaned:
        raise ValueError("refresh_token_slot cannot be empty")
    return cleaned
