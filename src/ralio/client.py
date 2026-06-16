"""The top-level :class:`RalioClient`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto, _store
from .auth import TokenManager
from .credentials import CredentialStore, LocalCredentialStore, StoredCredentials
from .errors import RalioConfigError
from .resources import (
    AgentsResource,
    ChatResource,
    PaymentIntentsResource,
    TransactionsResource,
)
from .transport import Transport


class RalioClient:
    """Synchronous client for the Ralio API, authenticated via a credential
    binding (OAuth 2.1 ``client_credentials`` + ``private_key_jwt`` + DPoP).

    After a one-time :func:`ralio.register` on this host, no configuration is
    needed::

        client = ralio.RalioClient()  # reads the persisted credentials
        reply = client.chat.send(message="What's my balance?")

    To manage credentials yourself, pass ``client_id`` and
    ``private_key_path`` together, or provide a ``credential_store``.
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        private_key_path: str | Path | None = None,
        base_url: str | None = None,
        scopes: list[str] | None = None,
        credential_store: CredentialStore | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = _store.resolve_base_url(base_url)
        resolved = _resolve_credentials(client_id, private_key_path, credential_store)
        private_key = resolved.private_key
        public_jwk = _crypto.public_jwk(private_key)
        kid = _crypto.jwk_thumbprint(public_jwk)

        # SSE streams need no read timeout; keep connect/write/pool bounded.
        self._http = httpx.Client(
            timeout=httpx.Timeout(timeout, read=None),
        )
        tokens = TokenManager(
            client_id=resolved.client_id,
            private_key=private_key,
            kid=kid,
            token_url=f"{self._base_url}/oauth/token",
            http=self._http,
            scopes=tuple(scopes) if scopes else None,
            refresh_token=resolved.refresh_token,
            credential_store=resolved.credential_store,
        )
        transport = Transport(
            base_url=self._base_url,
            http=self._http,
            tokens=tokens,
            private_key=private_key,
            public_jwk=public_jwk,
        )

        self.agents = AgentsResource(transport)
        self.chat = ChatResource(transport, self.agents)
        self.transactions = TransactionsResource(transport)
        self.payment_intents = PaymentIntentsResource(transport)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> RalioClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(frozen=True)
class _ResolvedCredentials:
    client_id: str
    private_key: EllipticCurvePrivateKey
    refresh_token: str | None
    credential_store: CredentialStore | None


def _resolve_credentials(
    client_id: str | None,
    private_key_path: str | Path | None,
    credential_store: CredentialStore | None,
) -> _ResolvedCredentials:
    """Resolve the binding handle and key material, falling back to the store."""
    if client_id and private_key_path:
        refresh_token = None
        if credential_store is not None:
            stored = credential_store.load_credentials()
            refresh_token = stored.refresh_token if stored is not None else None
        return _ResolvedCredentials(
            client_id=client_id,
            private_key=_load_private_key(Path(private_key_path)),
            refresh_token=refresh_token,
            credential_store=credential_store,
        )
    if client_id or private_key_path:
        raise RalioConfigError(
            "client_id and private_key_path must be passed together; omit both "
            "to use a credential_store or the credentials persisted by ralio.register()."
        )

    store = credential_store or LocalCredentialStore()
    stored = store.load_credentials()
    if stored is None or not stored.client_id:
        raise RalioConfigError(_missing_credentials_message(store))
    private_key = _load_private_key_from_stored(stored, store)
    return _ResolvedCredentials(
        client_id=stored.client_id,
        private_key=private_key,
        refresh_token=stored.refresh_token,
        credential_store=store,
    )


def _load_private_key(key_path: Path) -> EllipticCurvePrivateKey:
    try:
        return _crypto.load_private_key(key_path)
    except FileNotFoundError:
        raise RalioConfigError(
            f"Private key missing at {key_path} — the binding may have been "
            "revoked and the key removed. Re-run ralio.register() with a "
            "fresh ticket."
        ) from None


def _load_private_key_from_stored(
    stored: StoredCredentials,
    store: CredentialStore,
) -> EllipticCurvePrivateKey:
    try:
        if stored.private_key is not None:
            return stored.private_key
        if stored.private_key_pem is not None:
            return _crypto.load_private_key_pem(stored.private_key_pem)
        if stored.private_jwk is not None:
            return _crypto.load_private_key_jwk(stored.private_jwk)
        if stored.private_key_path:
            return _load_private_key(Path(stored.private_key_path))
    except ValueError as exc:
        raise RalioConfigError(f"Invalid Ralio private key material: {exc}") from None
    raise RalioConfigError(_missing_credentials_message(store))


def _missing_credentials_message(store: CredentialStore) -> str:
    if isinstance(store, LocalCredentialStore):
        return (
            f"No Ralio credentials found at {store.credentials_path}. Run "
            "ralio.register() on this host first, or pass client_id and "
            "private_key_path explicitly."
        )
    return (
        "credential_store.load_credentials() must return client_id and private "
        "key material for RalioClient."
    )
