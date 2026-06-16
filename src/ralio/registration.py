"""One-time credential-binding registration (the operator side).

The owner mints a ``ralio-reg-…`` ticket in the console — that is where
consent happens. The operator calls :func:`register` on the agent host: it
generates a P-256 keypair locally and submits the public key with the ticket;
the binding is active as soon as the server responds. The owner gets an email
receipt with a revoke link. The private key never leaves the host.

On activation the first access token is minted and the credentials are
persisted to ``~/.ralio/``, so a no-argument ``RalioClient()`` works from then
on.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto, _store
from ._store import DEFAULT_BASE_URL
from .credentials import CredentialStore, LocalCredentialStore, StoredCredentials
from .errors import RalioConfigError, RalioRegistrationError, raise_for_response
from .types import CredentialBinding

__all__ = ["DEFAULT_BASE_URL", "register"]


def register(
    *,
    ticket: str | None = None,
    private_key_path: str | Path | None = None,
    base_url: str | None = None,
    requested_scopes: list[str] | None = None,
    client_metadata: dict[str, Any] | None = None,
    credential_store: CredentialStore | None = None,
    overwrite: bool = False,
) -> CredentialBinding:
    """Register this host and return the active binding.

    One call, immediate activation: generates a keypair, writes the private
    key to disk, and submits the public key with the ticket. The binding is
    active when the server responds — there is no owner-approval step
    (consent happened when the owner minted the ticket; they receive an email
    receipt with a revoke link). The first access token is then minted and
    the credentials persisted, so ``RalioClient()`` needs no arguments
    afterwards.

    *ticket* defaults to the ``RALIO_REGISTRATION_TICKET`` environment
    variable. *private_key_path* defaults to ``~/.ralio/keys/<jkt>.pem`` inside
    the shared credential store; set *overwrite* to replace an existing file at
    an explicit path. Pass *credential_store* to persist the resulting
    ``client_id``, private key, and initial refresh token outside the default
    local store.

    Raises :class:`RalioRegistrationError` when the ticket is invalid,
    expired, or already consumed, or the public key is unusable.
    """
    resolved_ticket = (ticket or os.environ.get("RALIO_REGISTRATION_TICKET", "")).strip()
    if not resolved_ticket:
        raise RalioConfigError(
            "Missing registration ticket: pass ticket= or set RALIO_REGISTRATION_TICKET. "
            "Mint one in the console at Settings → Credentials."
        )
    base = _store.resolve_base_url(base_url)

    private_key, public_jwk = _crypto.generate_keypair()
    fingerprint = _crypto.jwk_thumbprint(public_jwk)

    store = credential_store or LocalCredentialStore()
    key_path: Path | None = None
    wrote_local_key = False

    if private_key_path is not None:
        key_path = Path(private_key_path)
        if key_path.exists() and not overwrite:
            raise RalioRegistrationError(
                f"{key_path} already exists; pass overwrite=True to replace it"
            )
        _crypto.save_private_key(key_path, private_key)
        wrote_local_key = True
    elif isinstance(store, LocalCredentialStore):
        store.ensure_keys_dir()
        key_path = store.key_path_for(fingerprint)
        _crypto.save_private_key(key_path, private_key)
        wrote_local_key = True
    else:
        # Custom stores receive the private key only after the server accepts
        # the registration, so a failed ticket does not leave orphaned secrets.
        key_path = None

    with httpx.Client(timeout=30.0) as http:
        try:
            payload = _submit(
                http, base, resolved_ticket, public_jwk, requested_scopes, client_metadata
            )
        except BaseException:
            # No binding was created — a key bound to nothing is dead weight.
            if wrote_local_key and key_path is not None:
                _store.delete_private_key(key_path)
            raise

        # The server echoes the RFC 7638 thumbprint it computed. A mismatch
        # means the binding went live under a key this host does not hold
        # (our public key was rewritten in flight, or a server bug) — the
        # credential must be revoked, not used.
        server_fingerprint = payload.get("fingerprint")
        client_id = payload.get("client_id")
        if server_fingerprint and server_fingerprint != fingerprint:
            if wrote_local_key and key_path is not None:
                _store.delete_private_key(key_path)
            handle = f" {client_id}" if isinstance(client_id, str) and client_id else ""
            raise RalioRegistrationError(
                "fingerprint mismatch between local key and server response: the "
                f"binding{handle} is live under a key this host does not hold — "
                "revoke it in the console at Settings → Credentials"
            )

        if not isinstance(client_id, str) or not client_id:
            # Pre-cutover server: it created a pending binding for our public
            # key and expects owner approval + polling. Keep the key — the
            # owner may still approve the pending binding on the old flow.
            raise RalioRegistrationError(
                "registration response did not include a client_id — this server "
                "still requires owner approval; upgrade the server to synchronous "
                f"activation (the private key was kept at {key_path})"
            )

        token = _mint_first_token(http, base, client_id, private_key, fingerprint)

    store.save_credentials(
        StoredCredentials(
            client_id=client_id,
            private_key=private_key,
            private_key_path=key_path,
            public_jwk=public_jwk,
            key_jkt=fingerprint,
            refresh_token=token.get("refresh_token") or None,
            extra={
                "access_token": token["access_token"],
                "expires_in": token.get("expires_in", 1800),
                "obtained_at": time.time(),
                "scope": token.get("scope", ""),
                "auth_method": "private_key_jwt",
            },
        )
    )

    scope = token.get("scope")
    scopes = (
        tuple(scope.split())
        if isinstance(scope, str) and scope
        else tuple(requested_scopes or ())
    )
    return CredentialBinding(client_id=client_id, scopes=scopes, key_path=str(key_path or ""))


def _submit(
    http: httpx.Client,
    base: str,
    ticket: str,
    public_jwk: dict[str, str],
    requested_scopes: list[str] | None,
    client_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"ticket": ticket, "public_key_jwk": public_jwk}
    if requested_scopes:
        body["requested_scopes"] = requested_scopes
    if client_metadata:
        body["client_metadata"] = client_metadata
    response = http.post(f"{base}/api/credential-bindings/registrations", json=body)
    if not response.is_success:
        raise RalioRegistrationError(_registration_error_message(response))
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _registration_error_message(response: httpx.Response) -> str:
    """Render the registration endpoint's error detail.

    The endpoint reports ``invalid_ticket``, ``ticket_expired``,
    ``ticket_already_consumed``, ``public_key_already_in_use``,
    ``invalid_public_key``, ``invalid_scope``, and
    ``scope_exceeds_ticket_ceiling``; ``error_description`` is preferred. For
    a consumed ticket the description tells a legitimate operator that
    someone else spent it and the owner should revoke the resulting
    credential; ``used_at`` / ``used_by_host`` are appended when the server
    knows them.
    """
    try:
        payload = response.json()
    except ValueError:
        payload = None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, str) and detail:
        return detail
    if isinstance(detail, dict):
        message = detail.get("error_description") or detail.get("error")
        if isinstance(message, str) and message:
            context = []
            used_at = detail.get("used_at")
            if isinstance(used_at, str) and used_at:
                context.append(f"used at {used_at}")
            used_by_host = detail.get("used_by_host")
            if isinstance(used_by_host, str) and used_by_host:
                context.append(f"by {used_by_host}")
            return f"{message} ({', '.join(context)})" if context else message
    return f"registration failed: HTTP {response.status_code}"


def _mint_first_token(
    http: httpx.Client,
    base: str,
    client_id: str,
    private_key: EllipticCurvePrivateKey,
    kid: str,
) -> dict[str, Any]:
    """Mint the first access token via ``client_credentials`` + ``private_key_jwt``.

    No ``scope`` parameter: the grant inherits the binding's full scope
    ceiling, which the response echoes back.
    """
    token_url = f"{base}/oauth/token"
    assertion = _crypto.sign_client_assertion(
        private_key, client_id=client_id, audience=token_url, kid=kid
    )
    response = http.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": _crypto.CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    raise_for_response(response)
    token = response.json()
    if not isinstance(token, dict) or not token.get("access_token"):
        raise RalioRegistrationError("token endpoint returned no access_token")
    return token
