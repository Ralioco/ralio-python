import pytest

import ralio
from ralio import _crypto

BASE_URL = "https://api.ralio.co"


@pytest.fixture
def key_file(tmp_path):
    key, _ = _crypto.generate_keypair()
    path = tmp_path / "ralio-key.pem"
    _crypto.save_private_key(path, key)
    return str(path)


@pytest.fixture
def client(key_file):
    c = ralio.RalioClient(client_id="cb_test", private_key_path=key_file, base_url=BASE_URL)
    yield c
    c.close()


@pytest.fixture
def token_response():
    return {
        "access_token": "access-1",
        "token_type": "DPoP",
        "expires_in": 1800,
        "refresh_token": "rrt-1",
        "scope": "agents:execute transactions:read",
    }


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Point the credential store at a fresh temp directory and neutralize any
    ambient RALIO_* env config (the store treats empty strings as unset)."""
    d = tmp_path / "ralio-config"
    monkeypatch.setenv("RALIO_CONFIG_DIR", str(d))
    monkeypatch.setenv("RALIO_API_URL", "")
    monkeypatch.setenv("RALIO_REGISTRATION_TICKET", "")
    return d
