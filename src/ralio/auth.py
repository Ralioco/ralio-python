"""Access-token lifecycle for the machine path.

A :class:`TokenManager` mints tokens via the ``private_key_jwt`` client
assertion, caches the access token until shortly before expiry, and rotates
the refresh token. All token mutations are serialised behind a lock:

> Presenting a previously-rotated refresh token is treated as a replay attack
> and revokes the whole chain.

so two threads must never race a refresh.
"""

from __future__ import annotations

import threading
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto
from .errors import raise_for_response


class TokenManager:
    def __init__(
        self,
        *,
        client_id: str,
        private_key: EllipticCurvePrivateKey,
        kid: str,
        token_url: str,
        http: httpx.Client,
        scopes: tuple[str, ...] | None = None,
        refresh_leeway_seconds: float = 300.0,
    ) -> None:
        self._client_id = client_id
        self._private_key = private_key
        self._kid = kid
        self._token_url = token_url
        self._http = http
        self._scopes = scopes
        self._leeway = refresh_leeway_seconds

        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at = 0.0

    def access_token(self) -> str:
        """Return a valid access token, minting or refreshing as needed."""
        with self._lock:
            if self._access_token and time.time() < self._expires_at - self._leeway:
                return self._access_token
            return self._obtain_locked()

    def force_refresh(self) -> str:
        """Discard the cached token and obtain a fresh one. Used after a 401."""
        with self._lock:
            self._access_token = None
            return self._obtain_locked()

    def _obtain_locked(self) -> str:
        if self._refresh_token:
            try:
                return self._refresh_locked()
            except Exception:
                # Refresh chains can be revoked or expired; fall back to a
                # fresh client-assertion mint, which always works while the
                # binding is active.
                self._refresh_token = None
        return self._mint_locked()

    def _mint_locked(self) -> str:
        assertion = _crypto.sign_client_assertion(
            self._private_key,
            client_id=self._client_id,
            audience=self._token_url,
            kid=self._kid,
        )
        data = {
            "grant_type": "client_credentials",
            "client_assertion_type": _crypto.CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        }
        if self._scopes:
            data["scope"] = " ".join(self._scopes)
        return self._exchange_locked(data)

    def _refresh_locked(self) -> str:
        assert self._refresh_token is not None
        return self._exchange_locked(
            {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self._client_id,
            }
        )

    def _exchange_locked(self, data: dict[str, str]) -> str:
        response = self._http.post(
            self._token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        raise_for_response(response)
        body = response.json()
        self._access_token = body["access_token"]
        self._refresh_token = body.get("refresh_token") or self._refresh_token
        self._expires_at = time.time() + float(body.get("expires_in", 1800))
        return self._access_token
