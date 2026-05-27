import hashlib

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from ralio import _crypto


def test_generate_keypair_returns_canonical_jwk():
    key, jwk = _crypto.generate_keypair()
    assert isinstance(key, EllipticCurvePrivateKey)
    assert list(jwk.keys()) == ["crv", "kty", "x", "y"]
    assert jwk["crv"] == "P-256"
    assert jwk["kty"] == "EC"
    assert "=" not in jwk["x"] and "=" not in jwk["y"]


def test_thumbprint_is_stable_and_unpadded():
    _, jwk = _crypto.generate_keypair()
    t1 = _crypto.jwk_thumbprint(jwk)
    t2 = _crypto.jwk_thumbprint(dict(reversed(list(jwk.items()))))
    assert t1 == t2  # key order must not matter
    assert "=" not in t1


def test_save_and_load_roundtrip(tmp_path):
    key, jwk = _crypto.generate_keypair()
    path = tmp_path / "k.pem"
    _crypto.save_private_key(path, key)
    assert (path.stat().st_mode & 0o777) == 0o600
    loaded = _crypto.load_private_key(path)
    assert _crypto.public_jwk(loaded) == jwk


def test_client_assertion_claims():
    key, jwk = _crypto.generate_keypair()
    kid = _crypto.jwk_thumbprint(jwk)
    token = _crypto.sign_client_assertion(
        key, client_id="cb_x", audience="https://api.ralio.co/oauth/token", kid=kid
    )
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "ES256"
    assert header["kid"] == kid
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == claims["sub"] == "cb_x"
    assert claims["aud"] == "https://api.ralio.co/oauth/token"
    assert claims["exp"] - claims["iat"] <= 300


def test_dpop_proof_binds_token_and_request():
    key, jwk = _crypto.generate_keypair()
    token = "access-token-value"
    proof = _crypto.sign_dpop_proof(
        key, method="get", url="https://api.ralio.co/api/transactions", access_token=token, jwk=jwk
    )
    header = pyjwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["jwk"] == jwk
    claims = pyjwt.decode(proof, options={"verify_signature": False})
    assert claims["htm"] == "GET"
    assert claims["htu"] == "https://api.ralio.co/api/transactions"
    expected_ath = _crypto.b64url(hashlib.sha256(token.encode()).digest())
    assert claims["ath"] == expected_ath


def test_dpop_proof_signature_verifies_against_public_key():
    key, jwk = _crypto.generate_keypair()
    proof = _crypto.sign_dpop_proof(
        key, method="GET", url="https://api.ralio.co/x", access_token="t", jwk=jwk
    )
    public_pem = key.public_key()
    # Should not raise — signature is valid for the embedded key.
    pyjwt.decode(proof, public_pem, algorithms=["ES256"], options={"verify_aud": False})


def test_load_rejects_non_ec_key(tmp_path):
    path = tmp_path / "bad.pem"
    path.write_bytes(b"not a key")
    with pytest.raises(ValueError):
        _crypto.load_private_key(path)
