"""The top-level :class:`RalioClient`."""

from __future__ import annotations

from pathlib import Path
from types import TracebackType

import httpx

from . import _crypto
from .auth import TokenManager
from .registration import DEFAULT_BASE_URL
from .resources import ChatResource, TransactionsResource
from .transport import Transport


class RalioClient:
    """Synchronous client for the Ralio API, authenticated via a credential
    binding (OAuth 2.1 ``client_credentials`` + ``private_key_jwt`` + DPoP).

    Obtain ``client_id`` and the private key once via :func:`ralio.register`,
    then::

        client = ralio.RalioClient(
            client_id="cb_...",
            private_key_path="ralio-key.pem",
        )
        reply = client.chat.send(agent_id="...", message="What's my balance?")
    """

    def __init__(
        self,
        *,
        client_id: str,
        private_key_path: str | Path,
        base_url: str = DEFAULT_BASE_URL,
        scopes: list[str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        private_key = _crypto.load_private_key(private_key_path)
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

        self.chat = ChatResource(transport)
        self.transactions = TransactionsResource(transport)

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
