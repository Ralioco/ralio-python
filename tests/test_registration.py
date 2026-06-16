import json

import httpx
import jwt as pyjwt
import pytest
import respx

import ralio
from ralio import _store
from ralio.credentials import StoredCredentials
from ralio.errors import RalioConfigError, RalioRegistrationError

BASE_URL = "https://api.ralio.co"
REG = f"{BASE_URL}/api/credential-bindings/registrations"
TOKEN_URL = f"{BASE_URL}/oauth/token"


def mock_activated_registration(token_response, client_id="cb_new"):
    """Mock a registration that activates synchronously on submit."""
    respx.post(REG).mock(return_value=httpx.Response(201, json={"client_id": client_id}))
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_response))


def stored_credentials():
    return json.loads(_store.credentials_path().read_text())


class CaptureCredentialStore:
    def __init__(self):
        self.saved_credentials: StoredCredentials | None = None
        self.refresh_token: str | None = None

    def load_credentials(self) -> StoredCredentials | None:
        return self.saved_credentials

    def save_credentials(self, credentials: StoredCredentials) -> None:
        self.saved_credentials = credentials
        self.refresh_token = credentials.refresh_token

    def save_refresh_token(self, refresh_token: str) -> None:
        self.refresh_token = refresh_token


@respx.mock
def test_register_happy_path(tmp_path, config_dir, token_response):
    mock_activated_registration(token_response)

    key_path = tmp_path / "k.pem"
    binding = ralio.register(
        ticket="ralio-reg-x",
        private_key_path=key_path,
        base_url=BASE_URL,
        requested_scopes=["agents:execute"],
    )

    assert binding.client_id == "cb_new"
    assert binding.key_path == str(key_path)
    # Scopes echo the token grant, not the request.
    assert binding.scopes == ("agents:execute", "transactions:read")
    assert key_path.exists()

    # One POST to the registration endpoint, no polling.
    reg_calls = [c for c in respx.calls if str(c.request.url).startswith(REG)]
    assert len(reg_calls) == 1
    assert b'"public_key_jwk"' in reg_calls[0].request.content

    # First mint: client_credentials with a private_key_jwt assertion.
    mint = next(c for c in respx.calls if str(c.request.url) == TOKEN_URL)
    form = dict(httpx.QueryParams(mint.request.content.decode()))
    assert form["grant_type"] == "client_credentials"
    claims = pyjwt.decode(form["client_assertion"], options={"verify_signature": False})
    assert claims["iss"] == "cb_new"
    assert claims["sub"] == "cb_new"
    assert claims["aud"] == TOKEN_URL

    # Persisted credentials are the CLI-compatible shape.
    stored = stored_credentials()
    assert stored["client_id"] == "cb_new"
    assert stored["access_token"] == "access-1"
    assert stored["refresh_token"] == "rrt-1"
    assert stored["auth_method"] == "private_key_jwt"
    assert stored["key_path"] == str(key_path)
    assert stored["key_jkt"]


@respx.mock
def test_register_env_ticket_and_default_key_path(config_dir, monkeypatch, token_response):
    monkeypatch.setenv("RALIO_REGISTRATION_TICKET", "ralio-reg-env")
    mock_activated_registration(token_response)

    binding = ralio.register(base_url=BASE_URL)

    assert binding.client_id == "cb_new"
    stored = stored_credentials()
    assert binding.key_path == str(_store.key_path_for(stored["key_jkt"]))
    assert binding.key_path.startswith(str(config_dir / "keys"))
    assert (config_dir / "keys" / f"{stored['key_jkt']}.pem").exists()

    submitted = json.loads(respx.calls[0].request.content)
    assert submitted["ticket"] == "ralio-reg-env"


@respx.mock
def test_register_can_persist_to_custom_credential_store(config_dir, token_response):
    mock_activated_registration(token_response)
    store = CaptureCredentialStore()

    binding = ralio.register(
        ticket="ralio-reg-x",
        base_url=BASE_URL,
        credential_store=store,
    )

    assert binding.client_id == "cb_new"
    assert binding.key_path == ""
    assert store.saved_credentials is not None
    assert store.saved_credentials.client_id == "cb_new"
    assert store.saved_credentials.private_key is not None
    assert store.saved_credentials.public_jwk is not None
    assert store.saved_credentials.key_jkt
    assert store.refresh_token == "rrt-1"
    assert _store.load_credentials() is None


def test_register_missing_ticket(config_dir):
    with pytest.raises(RalioConfigError, match="RALIO_REGISTRATION_TICKET"):
        ralio.register(base_url=BASE_URL)


@respx.mock
def test_register_consumed_ticket_surfaces_context(tmp_path, config_dir):
    respx.post(REG).mock(
        return_value=httpx.Response(
            409,
            json={
                "detail": {
                    "error": "ticket_already_consumed",
                    "error_description": (
                        "This ticket was already used. If that wasn't you, ask the "
                        "owner to revoke the resulting credential in the console."
                    ),
                    "used_at": "2026-06-10T09:00:00Z",
                    "used_by_host": "ci-runner-7",
                }
            },
        )
    )

    key_path = tmp_path / "k.pem"
    with pytest.raises(RalioRegistrationError) as err:
        ralio.register(ticket="t", private_key_path=key_path, base_url=BASE_URL)

    message = str(err.value)
    assert "already used" in message
    assert "revoke" in message
    assert "used at 2026-06-10T09:00:00Z" in message
    assert "by ci-runner-7" in message
    # The orphaned key is removed and nothing is persisted.
    assert not key_path.exists()
    assert _store.load_credentials() is None


@respx.mock
def test_register_maps_bare_error_codes(config_dir):
    respx.post(REG).mock(
        return_value=httpx.Response(410, json={"detail": {"error": "ticket_expired"}})
    )
    with pytest.raises(RalioRegistrationError, match="ticket_expired"):
        ralio.register(ticket="t", base_url=BASE_URL)


@respx.mock
def test_register_maps_validation_errors(config_dir):
    respx.post(REG).mock(
        return_value=httpx.Response(
            422,
            json={
                "detail": {
                    "error": "scope_exceeds_ticket_ceiling",
                    "error_description": "requested scope exceeds the ticket's ceiling",
                }
            },
        )
    )
    with pytest.raises(RalioRegistrationError, match="exceeds the ticket's ceiling"):
        ralio.register(ticket="t", base_url=BASE_URL)


@respx.mock
def test_register_aborts_on_fingerprint_mismatch(tmp_path, config_dir):
    respx.post(REG).mock(
        return_value=httpx.Response(201, json={"fingerprint": "tampered", "client_id": "cb_live"})
    )

    key_path = tmp_path / "k.pem"
    with pytest.raises(RalioRegistrationError) as err:
        ralio.register(ticket="t", private_key_path=key_path, base_url=BASE_URL)

    message = str(err.value)
    assert "fingerprint mismatch" in message
    assert "cb_live" in message
    assert "revoke" in message
    assert not key_path.exists()
    assert _store.load_credentials() is None


@respx.mock
def test_register_pre_cutover_server_keeps_key(tmp_path, config_dir):
    # An old server returns 202 with a poll token instead of a client_id.
    respx.post(REG).mock(return_value=httpx.Response(202, json={"poll_token": "pt_1"}))

    key_path = tmp_path / "k.pem"
    with pytest.raises(RalioRegistrationError) as err:
        ralio.register(ticket="t", private_key_path=key_path, base_url=BASE_URL)

    message = str(err.value)
    assert "owner approval" in message
    assert "upgrade the server" in message
    assert key_path.exists()


def test_register_refuses_to_overwrite(tmp_path, config_dir):
    key_path = tmp_path / "k.pem"
    key_path.write_text("existing")
    with pytest.raises(RalioRegistrationError, match="already exists"):
        ralio.register(ticket="t", private_key_path=key_path, base_url=BASE_URL)
    assert key_path.read_text() == "existing"
