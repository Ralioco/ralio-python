"""ES256 / DPoP crypto primitives for the Ralio machine-auth path.

Everything here mirrors what the Ralio API expects byte-for-byte:

- P-256 (ES256) is the only curve the token endpoint accepts.
- The public JWK is the canonical RFC 7638 form (``crv``/``kty``/``x``/``y``
  only, sorted), so the thumbprint computed here matches the ``cnf.jkt`` the
  server stamps on the access token and the fingerprint the owner confirms.
- Client assertions follow RFC 7521/7523; DPoP proofs follow RFC 9449.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# The server rejects assertions older than 300s; stay well under to absorb skew.
_CLIENT_ASSERTION_TTL_SECONDS = 60
_SECRET_FILE_MODE = 0o600


def b64url(raw: bytes) -> str:
    """Unpadded base64url — the only form RFC 7515/7517/7638 accept."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_keypair() -> tuple[EllipticCurvePrivateKey, dict[str, str]]:
    """Mint a P-256 keypair and return ``(private_key, canonical_public_jwk)``."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, public_jwk(private_key)


def public_jwk(private_key: EllipticCurvePrivateKey) -> dict[str, str]:
    """Return the canonical RFC 7638 public JWK for *private_key*."""
    numbers = private_key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }


def private_jwk(private_key: EllipticCurvePrivateKey) -> dict[str, str]:
    """Return the private P-256 JWK for *private_key*."""
    numbers = private_key.private_numbers()
    jwk = public_jwk(private_key)
    jwk["d"] = b64url(numbers.private_value.to_bytes(32, "big"))
    return jwk


def jwk_thumbprint(canonical_jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint of a canonical JWK — used as ``kid`` and key id."""
    canonical_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical_json.encode("ascii")).digest())


def save_private_key(path: str | Path, private_key: EllipticCurvePrivateKey) -> Path:
    """Write *private_key* as PKCS8 PEM at *path*, mode 0600, atomically."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
    try:
        with contextlib.suppress(OSError, AttributeError):
            # fchmod unavailable on Windows; set perms before any bytes land.
            os.fchmod(tmp_fd, _SECRET_FILE_MODE)
        with os.fdopen(tmp_fd, "wb") as f:
            tmp_fd = -1
            f.write(pem)
        os.replace(tmp_path, dest)
    except BaseException:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return dest


def load_private_key(path: str | Path) -> EllipticCurvePrivateKey:
    """Load a PKCS8 PEM P-256 private key from *path*."""
    return load_private_key_pem(Path(path).read_bytes())


def load_private_key_pem(data: str | bytes) -> EllipticCurvePrivateKey:
    """Load a PKCS8 PEM P-256 private key from bytes or text."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, EllipticCurvePrivateKey):
        raise ValueError("Ralio credentials require a P-256 (EC) private key")
    return key


def load_private_key_jwk(jwk: Mapping[str, str]) -> EllipticCurvePrivateKey:
    """Load a private P-256 key from an EC JWK with ``d``/``x``/``y`` members."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Ralio private JWKs must be P-256 EC keys")
    try:
        d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    except KeyError as exc:
        raise ValueError(f"Ralio private JWK is missing {exc.args[0]!r}") from None
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
    return private_numbers.private_key()


def sign_client_assertion(
    private_key: EllipticCurvePrivateKey,
    *,
    client_id: str,
    audience: str,
    kid: str,
    ttl_seconds: int = _CLIENT_ASSERTION_TTL_SECONDS,
) -> str:
    """Sign an RFC 7523 JWT bearer client assertion.

    ``iss`` and ``sub`` both equal *client_id*; ``aud`` is the absolute token
    endpoint URL. ``kid`` is the JWK thumbprint so the server can locate the
    binding directly.
    """
    iat = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": iat,
        "exp": iat + ttl_seconds,
        "jti": secrets.token_urlsafe(16),
    }
    return pyjwt.encode(payload, _pem(private_key), algorithm="ES256", headers={"kid": kid})


def sign_dpop_proof(
    private_key: EllipticCurvePrivateKey,
    *,
    method: str,
    url: str,
    access_token: str,
    jwk: dict[str, str],
) -> str:
    """Sign a single-use DPoP proof (RFC 9449) for one method + URL + token.

    *url* must already have its query and fragment stripped (``htu`` per
    RFC 9449 §4.2). The embedded ``jwk`` must be the canonical public JWK so
    its thumbprint matches the access token's ``cnf.jkt``.
    """
    iat = int(time.time())
    payload: dict[str, Any] = {
        "htm": method.upper(),
        "htu": url,
        "iat": iat,
        "jti": secrets.token_urlsafe(16),
        "ath": b64url(hashlib.sha256(access_token.encode("ascii")).digest()),
    }
    return pyjwt.encode(
        payload,
        _pem(private_key),
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "alg": "ES256", "jwk": dict(jwk)},
    )


def _pem(private_key: EllipticCurvePrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
