# Credential stores and clustered clients

`RalioClient()` works with the local `~/.ralio/credentials.json` written by
`ralio.register()`. For non-local storage, provide a small credential store
implementation.

The store is responsible for loading stable machine identity material:

- `client_id`
- private key material, as a key object, PEM, private JWK, or key path
- optional public JWK or key metadata
- the current refresh token for this SDK instance

It also receives refresh-token updates after token rotation.

```python
import json
import os
import ralio


class EnvAndVolumeStore:
    def __init__(self, instance_id: str):
        self.path = f"/var/run/ralio-refresh/{instance_id}.txt"

    def load_credentials(self):
        refresh_token = None
        if os.path.exists(self.path):
            with open(self.path) as f:
                refresh_token = f.read().strip()
        return ralio.StoredCredentials(
            client_id=os.environ["RALIO_CLIENT_ID"],
            private_jwk=json.loads(os.environ["RALIO_PRIVATE_JWK"]),
            refresh_token=refresh_token,
        )

    def save_credentials(self, credentials):
        if credentials.refresh_token:
            self.save_refresh_token(credentials.refresh_token)

    def save_refresh_token(self, refresh_token: str):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            f.write(refresh_token)


client = ralio.RalioClient(
    credential_store=EnvAndVolumeStore(instance_id=os.environ["HOSTNAME"])
)
```

Clustered instances should share the stable machine identity (`client_id` plus
the same private key/JWK) when they are the same logical client. They do not
need separate activation flows.

Refresh tokens are per running SDK instance / token family by default. Do not
point concurrent instances at one mutable refresh-token value unless you
explicitly want that behavior: refresh-token rotation races can make a reused
token look like a replay and revoke that family.

If you keep the default local file store on a mounted volume, give each worker
its own refresh-token slot while sharing the same credential directory:

```python
import os
import ralio

store = ralio.LocalCredentialStore(
    config_dir="/mnt/ralio-identity",
    refresh_token_slot=os.environ["HOSTNAME"],
)
client = ralio.RalioClient(credential_store=store)
```

Credential-wide revocation still revokes every refresh-token family for the
shared `client_id`.
