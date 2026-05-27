# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report security issues privately to **security@ralio.co**, or use GitHub's
[private vulnerability reporting](https://github.com/Ralioco/ralio-python/security/advisories/new)
on this repository.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- Affected version(s).

We aim to acknowledge reports within **2 business days** and to provide a
remediation timeline within **5 business days**. We'll keep you updated as we
work on a fix and will credit you in the advisory unless you prefer to remain
anonymous.

## Supported versions

This SDK is pre-1.0. Security fixes are released against the latest published
version on PyPI. Once 1.0 ships, we'll support the latest minor release line.

## Handling credentials

This SDK authenticates with a **P-256 private key** that must never leave the
host that generated it.

- The key is written to disk with mode `0600`; keep it that way.
- Never commit key files. The repository `.gitignore` excludes `*.pem` and
  `ralio-key*`, but you are responsible for your own integrations.
- If a key is exposed, revoke the credential binding in the Ralio console and
  re-register. There is no shared client secret to rotate — the key *is* the
  credential.
