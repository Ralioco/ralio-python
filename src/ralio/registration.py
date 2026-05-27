"""One-time credential-binding registration (the operator side).

The owner mints a ``ralio-reg-…`` ticket in the console. The operator calls
:func:`register` on the agent host: it generates a P-256 keypair locally,
submits the public key with the ticket, and polls until the owner approves the
binding in the console. The private key never leaves the host.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx

from . import _crypto
from .errors import RalioRegistrationError, raise_for_response
from .types import CredentialBinding

DEFAULT_BASE_URL = "https://api.ralio.co"
_TERMINAL = {"active", "rejected", "expired"}


def register(
    *,
    ticket: str,
    private_key_path: str | Path,
    base_url: str = DEFAULT_BASE_URL,
    requested_scopes: list[str] | None = None,
    client_metadata: dict[str, Any] | None = None,
    poll_interval: float = 3.0,
    timeout: float = 900.0,
    overwrite: bool = False,
) -> CredentialBinding:
    """Run the registration flow and return the approved binding.

    Generates a keypair, writes the private key to *private_key_path*, and
    blocks until the owner approves (up to *timeout* seconds). Raises
    :class:`RalioRegistrationError` if the binding is rejected, expires, or the
    timeout elapses.

    Set *overwrite* to replace an existing key file; by default an existing
    file is left untouched to avoid clobbering working credentials.
    """
    key_path = Path(private_key_path)
    if key_path.exists() and not overwrite:
        raise RalioRegistrationError(
            f"{key_path} already exists; pass overwrite=True to replace it"
        )

    base = base_url.rstrip("/")
    private_key, public_jwk = _crypto.generate_keypair()
    fingerprint = _crypto.jwk_thumbprint(public_jwk)
    _crypto.save_private_key(key_path, private_key)

    with httpx.Client(timeout=30.0) as http:
        poll_token = _submit(
            http, base, ticket, public_jwk, fingerprint, requested_scopes, client_metadata
        )
        client_id = _poll(http, base, poll_token, poll_interval, timeout)

    return CredentialBinding(
        client_id=client_id,
        scopes=tuple(requested_scopes or ()),
    )


def _submit(
    http: httpx.Client,
    base: str,
    ticket: str,
    public_jwk: dict[str, str],
    fingerprint: str,
    requested_scopes: list[str] | None,
    client_metadata: dict[str, Any] | None,
) -> str:
    body: dict[str, Any] = {"ticket": ticket, "public_key_jwk": public_jwk}
    if requested_scopes:
        body["requested_scopes"] = requested_scopes
    if client_metadata:
        body["client_metadata"] = client_metadata
    response = http.post(f"{base}/api/credential-bindings/registrations", json=body)
    raise_for_response(response)
    payload = response.json()

    # The server echoes the JWK thumbprint it computed. A mismatch means our
    # public key was rewritten in flight — refuse to proceed rather than let
    # the owner approve a binding for a key we don't hold.
    server_fingerprint = payload.get("fingerprint")
    if server_fingerprint and server_fingerprint != fingerprint:
        raise RalioRegistrationError(
            "fingerprint mismatch between local key and server response; aborting"
        )

    poll_token = payload.get("poll_token")
    if not isinstance(poll_token, str) or not poll_token:
        raise RalioRegistrationError("registration response did not include a poll_token")
    return poll_token


def _poll(
    http: httpx.Client,
    base: str,
    poll_token: str,
    interval: float,
    timeout: float,
) -> str:
    deadline = time.monotonic() + timeout
    url = f"{base}/api/credential-bindings/registrations/{poll_token}"
    while True:
        response = http.get(url)
        if response.status_code == 404:
            raise RalioRegistrationError("registration expired before approval")
        raise_for_response(response)
        body = response.json()
        status = body.get("status", "")
        if status == "active":
            client_id = body.get("client_id")
            if not isinstance(client_id, str) or not client_id:
                raise RalioRegistrationError("binding active but no client_id returned")
            return client_id
        if status in _TERMINAL:
            raise RalioRegistrationError(f"registration {status}")
        if time.monotonic() >= deadline:
            raise RalioRegistrationError("timed out waiting for owner approval")
        time.sleep(interval)
