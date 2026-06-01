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

> **Scope.** This SDK targets autonomous integrations (CI jobs, agent hosts,
> server-side callers). It authenticates as a **credential binding**, which can
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
   a scope ceiling. They send you the `ralio-reg-…` ticket.
2. You call `ralio.register(...)` on the agent host. It generates a keypair
   locally, submits the public key, and blocks until the owner approves the
   binding in the console. You get back a `client_id` (`cb_…`).
3. From then on, `RalioClient` mints and refreshes DPoP-bound access tokens
   transparently and signs a fresh proof for every request.

See the [API authentication guide](https://docs.ralio.co/api-reference/authentication)
for the protocol details.

## Register once

Run this on the host where the integration will live, after the owner sends you
a ticket:

```python
import ralio

binding = ralio.register(
    ticket="ralio-reg-...",
    private_key_path="ralio-key.pem",            # generated and written here
    requested_scopes=["agents:execute", "transactions:read"],
)
print(binding.client_id)   # cb_... — store this alongside the key
```

`register()` blocks until the owner approves (or the binding is rejected /
expires / times out). The private key never leaves the host.

> **Where does the agent ID come from?** `register()` returns a binding with
> `client_id` and `scopes` — the credential handle, **not** an agent ID. The
> agent you address in `chat.send(agent_id=...)` is the one the owner pinned the
> ticket to when minting it (chosen in the console; shown on the agent's
> settings page). Registration never echoes it back, so take `agent_id` from
> your own configuration — don't expect it on the `register()` result.

## Use the client

```python
import ralio

client = ralio.RalioClient(
    client_id="cb_...",
    private_key_path="ralio-key.pem",
)

# Synchronous chat
reply = client.chat.send(agent_id="d4e5...", message="What is my current balance?")
print(reply.reply)

# Streaming chat (server-sent events)
for event in client.chat.stream(agent_id="d4e5...", message="List my recent payments"):
    if event.event == "text_delta":
        print(event.text, end="", flush=True)
    elif event.event == "tool_started":
        print(f"\n[tool] {event.data['tool_name']}")

# Transactions
for txn in client.transactions.list(limit=20):
    print(txn.date, txn.amount, txn.currency, txn.creditor, txn.status)

client.close()
```

`RalioClient` is also a context manager:

```python
with ralio.RalioClient(client_id="cb_...", private_key_path="ralio-key.pem") as client:
    ...
```

## Payments

There is no `payments.create()` method by design. Payments are executed by the
**agent**, not by direct REST calls: drive the agent with `chat.send` /
`chat.stream` ("Pay £500 to Bob for the April invoice") and it will create the
payment, subject to its spend limits and approval rules. Use
`transactions.list` to read what the agent did.

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
| `RalioRegistrationError` | Registration rejected, expired, or timed out |
| `RalioConfigError` | Local configuration problem |

```python
import ralio

try:
    client.chat.send(agent_id="...", message="...")
except ralio.RalioPermissionError as exc:
    print("scope problem:", exc.detail)
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
