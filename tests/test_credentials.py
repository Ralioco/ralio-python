import httpx
import jwt as pyjwt
import respx

import ralio
from ralio import _crypto
from ralio.credentials import LocalCredentialStore, StoredCredentials

BASE_URL = "https://api.ralio.co"


class MemoryCredentialStore:
    def __init__(
        self,
        *,
        client_id: str,
        private_key=None,
        private_jwk=None,
        refresh_token: str | None = None,
    ):
        self.client_id = client_id
        self.private_key = private_key
        self.private_jwk = private_jwk
        self.refresh_token = refresh_token
        self.saved_credentials: StoredCredentials | None = None

    def load_credentials(self) -> StoredCredentials:
        return StoredCredentials(
            client_id=self.client_id,
            private_key=self.private_key,
            private_jwk=self.private_jwk,
            refresh_token=self.refresh_token,
        )

    def save_credentials(self, credentials: StoredCredentials) -> None:
        self.saved_credentials = credentials
        self.client_id = credentials.client_id
        self.private_key = credentials.private_key
        self.private_jwk = credentials.private_jwk
        self.refresh_token = credentials.refresh_token

    def save_refresh_token(self, refresh_token: str) -> None:
        self.refresh_token = refresh_token


def test_local_credential_store_saves_identity_and_instance_refresh(config_dir):
    private_key, public_jwk = _crypto.generate_keypair()
    jkt = _crypto.jwk_thumbprint(public_jwk)
    store = LocalCredentialStore(config_dir=config_dir, refresh_token_slot="worker/one")

    store.save_credentials(
        StoredCredentials(
            client_id="cb_local",
            private_key=private_key,
            refresh_token="rrt-1",
            extra={"scope": "agents:execute"},
        )
    )

    loaded = store.load_credentials()

    assert loaded is not None
    assert loaded.client_id == "cb_local"
    assert loaded.private_key_path == store.key_path_for(jkt)
    assert loaded.key_jkt == jkt
    assert loaded.refresh_token == "rrt-1"
    assert loaded.extra["scope"] == "agents:execute"
    assert store.key_path_for(jkt).exists()

    store.save_refresh_token("rrt-2")

    assert store.load_credentials().refresh_token == "rrt-2"
    assert (config_dir / "refresh-tokens" / "worker_one.json").exists()


@respx.mock
def test_client_uses_custom_credential_store(token_response):
    private_key, _ = _crypto.generate_keypair()
    store = MemoryCredentialStore(
        client_id="cb_custom",
        private_jwk=_crypto.private_jwk(private_key),
    )
    token_route = respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    with ralio.RalioClient(credential_store=store) as client:
        assert client.chat.send(agent_id="a1", message="hi").reply == "ok"

    form = dict(httpx.QueryParams(token_route.calls.last.request.content.decode()))
    assert form["grant_type"] == "client_credentials"
    claims = pyjwt.decode(form["client_assertion"], options={"verify_signature": False})
    assert claims["iss"] == "cb_custom"
    assert store.refresh_token == "rrt-1"


@respx.mock
def test_token_refresh_writes_updated_refresh_token_to_store():
    private_key, _ = _crypto.generate_keypair()
    store = MemoryCredentialStore(
        client_id="cb_refresh",
        private_key=private_key,
        refresh_token="rrt-old",
    )
    token_route = respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-refreshed",
                "token_type": "DPoP",
                "expires_in": 1800,
                "refresh_token": "rrt-new",
            },
        )
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    with ralio.RalioClient(credential_store=store) as client:
        assert client.chat.send(agent_id="a1", message="hi").reply == "ok"

    form = dict(httpx.QueryParams(token_route.calls.last.request.content.decode()))
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == "rrt-old"
    assert store.refresh_token == "rrt-new"


@respx.mock
def test_two_clients_share_identity_with_separate_refresh_tokens():
    private_key, _ = _crypto.generate_keypair()
    store_a = MemoryCredentialStore(
        client_id="cb_shared", private_key=private_key, refresh_token="rrt-a"
    )
    store_b = MemoryCredentialStore(
        client_id="cb_shared", private_key=private_key, refresh_token="rrt-b"
    )
    token_route = respx.post(f"{BASE_URL}/oauth/token").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "access_token": "access-a",
                    "token_type": "DPoP",
                    "expires_in": 1800,
                    "refresh_token": "rrt-a2",
                },
            ),
            httpx.Response(
                200,
                json={
                    "access_token": "access-b",
                    "token_type": "DPoP",
                    "expires_in": 1800,
                    "refresh_token": "rrt-b2",
                },
            ),
        ]
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    with ralio.RalioClient(credential_store=store_a) as client_a:
        assert client_a.chat.send(agent_id="a1", message="one").reply == "ok"
    with ralio.RalioClient(credential_store=store_b) as client_b:
        assert client_b.chat.send(agent_id="a1", message="two").reply == "ok"

    forms = [
        dict(httpx.QueryParams(call.request.content.decode()))
        for call in token_route.calls
    ]
    assert [form["client_id"] for form in forms] == ["cb_shared", "cb_shared"]
    assert [form["refresh_token"] for form in forms] == ["rrt-a", "rrt-b"]
    assert store_a.refresh_token == "rrt-a2"
    assert store_b.refresh_token == "rrt-b2"
