# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with a `zkcredit` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `ZKCREDIT_*` environment variables, checked at startup. `ZKCREDIT_ENV=production`
  refuses to start without `ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes`, `ZKCREDIT_FIP_PUBLIC_KEY`,
  hashed API keys and a database, holds no FIP signing key, and disables the demo prover and
  forged-proof demos. Every start logs that the cryptography is unreviewed.
- Per-client API keys with roles (`applicant`, `lender`, `bank`, `viewer`, `monitor`, `admin`),
  stored as `sha256:<hex>`; `python -m zkcredit.ops keygen` makes new ones. Replaces `ZKCREDIT_API_KEY`.
- Recorded credit verifications and published proofs of solvency (SQLite, or Postgres through
  `ZKCREDIT_DATABASE_URL`), with `GET /underwrite/verifications[/{id}]` and
  `GET /solvency/audits[/{id}]`; numbered migrations and `python -m zkcredit migrate`. The sampled
  customer's private inclusion proof is never stored.
- Per-client rate limit, body cap (also for chunked bodies), security headers, CORS only for listed
  origins; JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus `/metrics`.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- `/health` became `/params` (group parameters, FIP key source, review status) plus `/healthz`
  and `/readyz`. A malformed bundle gets "invalid CreditProofBundle" without the parser's message.
- The torsion test no longer asserts that libsodium accepts a torsion point: PyNaCl 1.6 (the
  locked version) rejects it itself. Our own subgroup check is still tested.

### Unchanged
- The cryptographic code and every benchmark number in the README.
