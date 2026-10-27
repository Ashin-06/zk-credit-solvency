# Runbook

How to deploy, configure and operate zkcredit. Commands assume the repository root. Read the
"Reference implementation, not production cryptography" note in the README first.

## Deploy

```bash
docker build -t zk-credit-solvency:1.0.0 .
python -m zkcredit.ops keygen               # one key per lender, bank and monitor
docker run -d --name zkcredit -p 8012:8012 -v zkcredit-data:/data \
  -e ZKCREDIT_KEYS_FILE=/run/secrets/zkcredit-keys.json \
  -e ZKCREDIT_FIP_PUBLIC_KEY=<FIP Ed25519 public key, 64 hex> \
  -e ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes \
  zk-credit-solvency:1.0.0
curl -fsS http://127.0.0.1:8012/readyz
```

The image runs in production mode as a non-root user with its SQLite database in `/data`. It
refuses to start, and logs why, without the acknowledgement, the FIP key, API keys or a database.
Setting `ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes` is a decision for whoever owns the risk, not a
deployment detail. Terminate TLS in front of it.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `zkcredit serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `ZKCREDIT_ENV` | — | `development` (default) or `production` |
| `ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO` | `yes` | acknowledges that the protocols are unreviewed |
| `ZKCREDIT_FIP_PUBLIC_KEY` | yes | the FIP's Ed25519 public key, 64 hex (development: a demo key per start) |
| `ZKCREDIT_API_KEYS` / `ZKCREDIT_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `lender` (verify, read), `bank` (publish solvency proofs, read), `viewer`, `applicant` (development prover), `monitor` (`/metrics`), `admin` |
| `ZKCREDIT_DATABASE_URL` | yes | `sqlite:////data/zkcredit.db` or `postgresql://...` (development default: in memory) |
| `ZKCREDIT_HOST`, `ZKCREDIT_PORT` | — | default `127.0.0.1:8012`; a non-loopback address needs API keys |
| `ZKCREDIT_RATE_LIMIT`, `ZKCREDIT_MAX_BODY_BYTES` | — | default 120/min per client, 1,000,000 bytes |
| `ZKCREDIT_CORS_ORIGINS`, `ZKCREDIT_LOG_LEVEL` | — | none by default; `INFO` |

## Watch

- `GET /healthz`: process up. `GET /readyz`: database answers.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `zkcredit_decisions_total{decision="credit_verified|credit_rejected|solvency_verified|solvency_rejected"}`.
- Logs: JSON lines with `request_id`; every start logs the unreviewed-cryptography warning.

Suggested alerts: `/readyz` failing; a jump in `credit_rejected` (a FIP key mismatch after the FIP
rotated, or forgery attempts); p95 verification latency above 3 s.

## Rotate keys

**API keys.** Add the new hash, restart, hand over the key, remove the old hash, restart.

**FIP key.** The service pins one FIP key. When the FIP rotates, bundles signed with the old key
stop verifying the moment you switch. Switch at the FIP's announced cut-over, and re-request
bundles from borrowers caught in between. If the FIP's key leaked, switch at once.

## Back up and restore

```bash
docker exec zkcredit python -c "import sqlite3; s=sqlite3.connect('/data/zkcredit.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp zkcredit:/data/backup.db ./zkcredit-$(date +%F).db
```

Restore: stop the container, put the backup at `/data/zkcredit.db`, start it, check `/readyz` and
`GET /solvency/audits`. Postgres: `pg_dump` / `pg_restore`; migrations run on start or with
`python -m zkcredit migrate`. Published solvency roots must stay available to customers: keep
backups for as long as a root may be checked.

## Incidents

1. **A flaw in a protocol is reported.** Stop accepting new verifications (revoke lender keys),
   treat recorded `verified` results as unproven, and get the report to a cryptographer before
   doing anything else.
2. **FIP key leaked.** Switch to the FIP's new key; re-verify recent approvals with fresh bundles.
3. **Leaked API key.** Remove its hash and restart; review that user's verifications and audits.
