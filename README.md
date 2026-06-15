# Ralio Python SDK

[![PyPI version](https://img.shields.io/pypi/v/ralio.svg)](https://pypi.org/project/ralio/)
[![Python versions](https://img.shields.io/pypi/pyversions/ralio.svg)](https://pypi.org/project/ralio/)
[![CI](https://github.com/Ralioco/ralio-python/actions/workflows/ci.yml/badge.svg)](https://github.com/Ralioco/ralio-python/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

The official Python client for the [Ralio](https://ralio.co) agentic payment API.

It handles the machine-authentication path end to end — OAuth 2.1
`client_credentials` with `private_key_jwt` and DPoP-bound access tokens — so
your integration can talk to an agent without hand-rolling JWT signing, proof
generation, or token refresh.

> **Scope.** This SDK targets autonomous integrations such as agent hosts,
> backend services, and other server-side automation. It authenticates as a
> **credential binding**, which can
> hold the `agents:execute` and `transactions:read` scopes. Agent and binding
> management (`agents:config`) is a human-only operation in the console and is
> intentionally not part of this SDK.

## Installation

```bash
pip install ralio
```

Requires Python 3.10+.

## Authentication model

Ralio's machine path has no shared secrets. Each credential is a P-256 private
key that lives on exactly one host:

1. The **owner** mints a one-time registration ticket in the console
   (**Settings → Credentials → New credential**), choosing the target agent and
   a scope ceiling. That is where consent happens. They send you the
   `ralio-reg-…` ticket.
2. You call `ralio.register()` once on the agent host. It generates a keypair
   locally and submits the public key with the ticket; the binding is active
   as soon as the server responds — no approval step, no polling. The owner
   gets an email receipt with a revoke link. The credentials are persisted to
   `~/.ralio/` — the same store the `ralio` CLI uses, so `register()` and
   `ralio auth agent` are interchangeable.
3. From then on, `RalioClient` mints and refreshes DPoP-bound access tokens
   transparently and signs a fresh proof for every request.

See the [API authentication guide](https://docs.ralio.co/api-reference/authentication)
for the protocol details.

## Quickstart

With the owner's ticket in `RALIO_REGISTRATION_TICKET`, onboarding is two
calls:

```python
import ralio

ralio.register()  # run once; the binding is active when this returns

client = ralio.RalioClient()  # zero-config: reads the persisted credentials
reply = client.chat.send(message="What is my current balance?")
```

`register()` activates the binding in a single call (or raises
`RalioRegistrationError` if the ticket is invalid, expired, or already
consumed). The private key is generated locally, written to
`~/.ralio/keys/<jkt>.pem`, and never leaves the host.

Everything is overridable when you want to manage credentials yourself:

```python
import ralio

binding = ralio.register(
    ticket="ralio-reg-...",                      # instead of RALIO_REGISTRATION_TICKET
    private_key_path="ralio-key.pem",            # generated and written here
    requested_scopes=["agents:execute", "transactions:read"],
)
print(binding.client_id)   # cb_... — store this alongside the key
```

## Use the client

```python
import ralio

# Zero-config: reads the credentials persisted by register() / `ralio auth agent`.
client = ralio.RalioClient()

# Or manage credentials yourself:
# client = ralio.RalioClient(
#     client_id="cb_...",
#     private_key_path="ralio-key.pem",
# )

# Synchronous chat uses the agent selected when this credential was registered.
reply = client.chat.send(message="What is my current balance?")
print(reply.reply)

# Streaming chat (server-sent events)
for event in client.chat.stream(message="List my recent payments"):
    if event.event == "text_delta":
        print(event.text, end="", flush=True)
    elif event.event == "tool_started":
        print(f"\n[tool] {event.data['tool_name']}")

# Transactions — list endpoints are paginated; a Page is iterable and sized.
page = client.transactions.list(per_page=20)
print(f"showing {len(page)} of {page.total} transactions (page {page.page})")
for txn in page:
    print(txn.date, txn.amount, txn.currency, txn.creditor, txn.status)

# Payment intents — what the agent proposed, with per-leg execution detail.
for intent in client.payment_intents.list(per_page=20):
    print(intent.created_at, intent.total_amount, intent.currency, intent.approval_status)

client.close()
```

`RalioClient` is also a context manager:

```python
with ralio.RalioClient() as client:
    ...
```

## Environment variables

| Variable                    | Meaning                                                              |
| --------------------------- | -------------------------------------------------------------------- |
| `RALIO_REGISTRATION_TICKET` | Default ticket for `register()` — same variable the CLI reads        |
| `RALIO_API_URL`             | API origin (default `https://api.ralio.co`)                          |
| `RALIO_CONFIG_DIR`          | Credential store location (default `~/.ralio`, shared with the CLI)  |

## Payments

There is no `payments.create()` method by design. Payments are executed by the
**agent**, not by direct REST calls: drive the agent with `chat.send` /
`chat.stream` ("Pay £500 to Bob for the April invoice") and it will create the
payment, subject to its spend limits and approval rules. Use
`transactions.list` (executed payments) and `payment_intents.list` (what the
agent proposed, with per-leg status) to read what the agent did.

## Errors

All errors subclass `ralio.RalioError`:

| Exception | When |
|-----------|------|
| `RalioAuthError` (401) | Missing/invalid token, failed assertion, or rejected DPoP proof |
| `RalioPermissionError` (403) | Token lacks the required scope, or resource not owned |
| `RalioNotFoundError` (404) | Resource doesn't exist |
| `RalioValidationError` (422) | Invalid field values or business-rule violation |
| `RalioRateLimitError` (429) | Rate limited — back off and retry |
| `RalioAPIError` | Any other HTTP error (carries `status_code`, `detail`) |
| `RalioRegistrationError` | Registration failed (invalid / expired / consumed ticket) |
| `RalioConfigError` | Local configuration problem |

```python
import ralio

try:
    client.chat.send(message="...")
except ralio.RalioPermissionError as exc:
    print("scope problem:", exc.detail)
```

The target agent is fixed by the authenticated credential. To use a different
agent, register or authenticate a new credential for that agent.

## Development

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
