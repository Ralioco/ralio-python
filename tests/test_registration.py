import httpx
import pytest
import respx

import ralio
from ralio.errors import RalioRegistrationError

BASE_URL = "https://api.ralio.co"
REG = f"{BASE_URL}/api/credential-bindings/registrations"


@respx.mock
def test_register_happy_path(tmp_path):
    # No fingerprint echoed -> the SDK skips the mismatch check (it only fires
    # when the server returns a fingerprint that differs from the local one).
    respx.post(REG).mock(
        return_value=httpx.Response(202, json={"poll_token": "pt_1"})
    )
    respx.get(f"{REG}/pt_1").mock(
        side_effect=[
            httpx.Response(200, json={"status": "pending_approval"}),
            httpx.Response(200, json={"status": "active", "client_id": "cb_new"}),
        ]
    )

    key_path = tmp_path / "k.pem"
    binding = ralio.register(
        ticket="ralio-reg-x",
        private_key_path=key_path,
        base_url=BASE_URL,
        requested_scopes=["agents:execute"],
        poll_interval=0,
    )

    assert binding.client_id == "cb_new"
    assert binding.scopes == ("agents:execute",)
    assert key_path.exists()
    # Public key submitted must be canonical.
    submitted = respx.calls[0].request
    assert b'"public_key_jwk"' in submitted.content


@respx.mock
def test_register_rejected(tmp_path):
    respx.post(REG).mock(
        return_value=httpx.Response(202, json={"poll_token": "pt_1"})
    )
    respx.get(f"{REG}/pt_1").mock(return_value=httpx.Response(200, json={"status": "rejected"}))

    with pytest.raises(RalioRegistrationError, match="rejected"):
        ralio.register(
            ticket="t", private_key_path=tmp_path / "k.pem", base_url=BASE_URL, poll_interval=0
        )


@respx.mock
def test_register_aborts_on_fingerprint_mismatch(tmp_path):
    respx.post(REG).mock(
        return_value=httpx.Response(202, json={"fingerprint": "tampered", "poll_token": "pt_1"})
    )
    with pytest.raises(RalioRegistrationError, match="fingerprint mismatch"):
        ralio.register(
            ticket="t", private_key_path=tmp_path / "k.pem", base_url=BASE_URL, poll_interval=0
        )


def test_register_refuses_to_overwrite(tmp_path):
    key_path = tmp_path / "k.pem"
    key_path.write_text("existing")
    with pytest.raises(RalioRegistrationError, match="already exists"):
        ralio.register(ticket="t", private_key_path=key_path, base_url=BASE_URL)
