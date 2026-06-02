# Changelog

## 0.1.0 (unreleased)

Initial release.

- OAuth 2.1 `client_credentials` + `private_key_jwt` + DPoP authentication.
- One-time credential-binding registration (`ralio.register`).
- `client.chat.send` and `client.chat.stream` (SSE). `agent_id` is optional —
  when omitted, the SDK resolves the single agent the credential is bound to
  (via `client.agents.list()`) and caches it.
- `client.agents.list` and the `Agent` type.
- `client.transactions.list`.
