# Changelog

## 0.1.0 (unreleased)

Initial release.

- OAuth 2.1 `client_credentials` + `private_key_jwt` + DPoP authentication.
- One-time credential-binding registration (`ralio.register`) with
  **synchronous activation** (server PR agentic-payment-gateway#1182): the
  binding is active as soon as the submit call returns — no owner-approval
  step, no polling. Ticket errors (`invalid_ticket`, `ticket_expired`,
  `ticket_already_consumed` with `used_at`/`used_by_host` context,
  `public_key_already_in_use`, `invalid_public_key`, `invalid_scope`,
  `scope_exceeds_ticket_ceiling`) map into `RalioRegistrationError`.
- Zero-config onboarding, in lockstep with the Node SDK
  (Ralioco/ralio-node#15): `register()` defaults its ticket to
  `RALIO_REGISTRATION_TICKET`, mints the first access token, and persists
  credentials to `~/.ralio/` (the CLI's store, so `register()` and
  `ralio auth agent` are interchangeable; private key at
  `~/.ralio/keys/<jkt>.pem`, `private_key_path` overrides). `RalioClient()`
  then constructs with no arguments. Env overrides: `RALIO_API_URL`,
  `RALIO_CONFIG_DIR`. `CredentialBinding` gained `key_path`; `scopes` now
  reflects the granted token scope.
- `client.chat.send` and `client.chat.stream` (SSE). `agent_id` is optional —
  when omitted, the SDK resolves the single agent the credential is bound to
  (via `client.agents.list()`) and caches it.
- `client.agents.list` and the `Agent` type.
- `client.transactions.list` and `client.payment_intents.list` (paginated).
