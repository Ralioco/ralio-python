# Contributing

Thanks for your interest in improving the Ralio Python SDK.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/Ralioco/ralio-python
cd ralio-python
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

All of these must pass before a PR is merged; CI runs them on Python 3.10–3.13.

```bash
ruff check .      # lint
mypy              # static types (strict)
pytest -q         # tests
```

Optionally install the pre-commit hooks so the lint/type checks run on every
commit:

```bash
pip install pre-commit && pre-commit install
```

## Guidelines

- **Public API.** Anything importable from `ralio` (not underscore-prefixed) is
  public and follows SemVer. Modules like `ralio._crypto` are internal and may
  change without notice.
- **Types.** Every public function, method, and attribute is type-annotated;
  `mypy --strict` must pass.
- **Tests.** New behavior needs tests. Network is mocked with `respx` — tests
  must not hit a live API. Crypto correctness (DPoP/assertion claims and
  signatures) is tested with real keys.
- **No new runtime dependencies** without discussion. The SDK intentionally
  depends only on `httpx` and `PyJWT[crypto]`.
- **Security-sensitive code** (key handling, signing, token lifecycle) gets
  extra review. If your change touches it, call that out in the PR.

## Commit messages & PRs

- Write a clear subject line in the imperative mood.
- Keep PRs focused; update `CHANGELOG.md` under the unreleased section.
- Link any related issue.

## Reporting bugs / requesting features

Use the issue templates. For security issues, see [SECURITY.md](SECURITY.md) —
do not file a public issue.
