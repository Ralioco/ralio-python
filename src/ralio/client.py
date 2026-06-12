"""The top-level :class:`RalioClient`."""

from __future__ import annotations

from pathlib import Path
from types import TracebackType

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto, _store
from .auth import TokenManager
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
    ``private_key_path`` together.
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        private_key_path: str | Path | None = None,
        base_url: str | None = None,
        scopes: list[str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = _store.resolve_base_url(base_url)
        client_id, key_path = _resolve_credentials(client_id, private_key_path)
        private_key = _load_private_key(key_path)
        public_jwk = _crypto.public_jwk(private_key)
        kid = _crypto.jwk_thumbprint(public_jwk)

        # SSE streams need no read timeout; keep connect/write/pool bounded.
        self._http = httpx.Client(
            timeout=httpx.Timeout(timeout, read=None),
        )
        tokens = TokenManager(
            client_id=client_id,
            private_key=private_key,
            kid=kid,
            token_url=f"{self._base_url}/oauth/token",
            http=self._http,
            scopes=tuple(scopes) if scopes else None,
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


def _resolve_credentials(
    client_id: str | None,
    private_key_path: str | Path | None,
) -> tuple[str, Path]:
    """Resolve the binding handle and key path, falling back to the store."""
    if client_id and private_key_path:
        return client_id, Path(private_key_path)
    if client_id or private_key_path:
        raise RalioConfigError(
            "client_id and private_key_path must be passed together; omit both "
            "to use the credentials persisted by ralio.register()."
        )

    stored = _store.load_credentials() or {}
    stored_client_id = stored.get("client_id")
    stored_key_path = stored.get("key_path")
    stored_jkt = stored.get("key_jkt")
    key_path: Path | None = None
    if isinstance(stored_key_path, str) and stored_key_path:
        key_path = Path(stored_key_path)
    elif isinstance(stored_jkt, str) and stored_jkt:
        key_path = _store.key_path_for(stored_jkt)
    if not isinstance(stored_client_id, str) or not stored_client_id or key_path is None:
        raise RalioConfigError(
            f"No Ralio credentials found at {_store.credentials_path()}. Run "
            "ralio.register() (or `ralio auth agent`) on this host first, or "
            "pass client_id and private_key_path explicitly."
        )
    return stored_client_id, key_path


def _load_private_key(key_path: Path) -> EllipticCurvePrivateKey:
    try:
        return _crypto.load_private_key(key_path)
    except FileNotFoundError:
        raise RalioConfigError(
            f"Private key missing at {key_path} — the binding may have been "
            "revoked and the key removed. Re-run ralio.register() with a "
            "fresh ticket."
        ) from None
