"""Zero-config construction: RalioClient() reading the persisted store."""

import httpx
import jwt as pyjwt
import pytest
import respx

import ralio
from ralio import _crypto, _store
from ralio.errors import RalioConfigError

BASE_URL = "https://api.ralio.co"
REG = f"{BASE_URL}/api/credential-bindings/registrations"


def seed_store(client_id="cb_stored"):
    """Persist a binding to the (stubbed) store, as register() would."""
    private_key, public_jwk = _crypto.generate_keypair()
    jkt = _crypto.jwk_thumbprint(public_jwk)
    _store.ensure_keys_dir()
    _crypto.save_private_key(_store.key_path_for(jkt), private_key)
    _store.save_credentials(
        {"client_id": client_id, "key_jkt": jkt, "auth_method": "private_key_jwt"}
    )


@respx.mock
def test_client_reads_persisted_credentials(config_dir, token_response):
    seed_store("cb_stored")
    token_route = respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    with ralio.RalioClient() as client:
        reply = client.chat.send(agent_id="a1", message="hi")
    assert reply.reply == "ok"

    # The minted assertion is for the stored client_id.
    form = dict(httpx.QueryParams(token_route.calls.last.request.content.decode()))
    claims = pyjwt.decode(form["client_assertion"], options={"verify_signature": False})
    assert claims["iss"] == "cb_stored"


def test_client_fails_clearly_without_credentials(config_dir):
    with pytest.raises(RalioConfigError, match=r"register\(\)"):
        ralio.RalioClient()


def test_client_rejects_partial_explicit_credentials(config_dir, key_file):
    with pytest.raises(RalioConfigError, match="together"):
        ralio.RalioClient(client_id="cb_x")
    with pytest.raises(RalioConfigError, match="together"):
        ralio.RalioClient(private_key_path=key_file)


def test_client_fails_clearly_when_key_file_is_missing(config_dir):
    seed_store()
    _store.key_path_for(_store.load_credentials()["key_jkt"]).unlink()
    with pytest.raises(RalioConfigError, match="Private key missing"):
        ralio.RalioClient()


@respx.mock
def test_register_then_zero_config_client_end_to_end(config_dir, monkeypatch, token_response):
    monkeypatch.setenv("RALIO_REGISTRATION_TICKET", "ralio-reg-e2e")
    respx.post(REG).mock(return_value=httpx.Response(201, json={"client_id": "cb_e2e"}))
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "done", "conversation_id": "c1", "new_messages": []}
        )
    )

    binding = ralio.register()
    assert binding.client_id == "cb_e2e"

    with ralio.RalioClient() as client:
        assert client.chat.send(agent_id="a1", message="hi").reply == "done"
