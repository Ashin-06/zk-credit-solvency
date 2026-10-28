# ZK Credit & Proof of Solvency

Two zero-knowledge checks that let a lender or regulator confirm facts about money without seeing the numbers:

1. Credit underwriting. A borrower proves that 12 months of bank statements meet a lender's policy: annual net cashflow above a floor, debt-to-income under a cap, and no month below a minimum balance. The lender sees only commitments, proofs and the statement bank's signature.
2. Proof of solvency. A bank publishes a tree of committed customer balances and proves that its reserves cover the total. Each customer can check that their own balance is included.

The protocols are built on libsodium's elliptic-curve arithmetic, but the commitment scheme, range proofs and tree are written in this project and have not been reviewed by a cryptographer. Treat the code as a readable model of the protocols, not as something to protect real money with.

## How it works

- Pedersen commitments (C = v·g + r·h on Ed25519) hide each number but can still be added, so the verifier can rebuild totals and ratios from the commitments alone.
- Range proofs show that a hidden value is above a threshold, using one OR-proof per bit.
- For credit, the statement bank signs the commitments, and the lender checks that signature before anything else. Without it a borrower could commit to invented figures.
- For solvency, each customer's leaf is labelled with a random nonce known only to them, nodes add up their children, and the bank proves reserves minus the total is not negative.

The full construction and its size limits are in [docs/design.md](docs/design.md).

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                       # 21 tests
python -m zkcredit bench                  # benchmark below
python -m zkcredit serve                  # API and console on http://127.0.0.1:8012
```

To build the container image: `docker build -t zk-credit-solvency .` (see [docs/runbook.md](docs/runbook.md)).

## API

| Endpoint | Purpose |
|---|---|
| `GET /params` | group parameters, the statement bank's public key and the review status of the cryptography |
| `GET /presets` | example borrowers and banks |
| `POST /underwrite/prove` | build a credit proof; the server plays every party, so this is for development only |
| `POST /underwrite/verify` | verify a credit proof; every verification is recorded |
| `GET /underwrite/verifications` | recorded verifications |
| `POST /solvency/audit` | build, check and publish a proof of solvency |
| `GET /solvency/audits` | published proofs and the roots customers check against |
| `GET /healthz`, `/readyz`, `/metrics` | health, readiness and Prometheus metrics |

Each caller gets an API key with a role: `lender`, `bank`, `viewer`, `applicant` (development prover only) or `monitor`. Create one with `python -m zkcredit.ops keygen`.

## Results

`python -m zkcredit bench` runs hand-written profiles:

| Case | Expected | Result |
|---|---|---|
| Salaried borrower, profitable small business | eligible | verified |
| Solvent bank (8 customers, ₹30 lakh reserves against ₹24 lakh owed) | solvent | verified |
| Debt-to-income 52.5% against a 40% cap, an overdrawn month, low cashflow | ineligible | rejected |
| Commitment swapped for a higher cashflow | reject | rejected |
| Negative balance hidden in the solvency tree | reject | rejected |
| Forged range proofs | reject | rejected |
| One proof value changed | reject | rejected |
| Borrower signs invented figures with their own key | reject | rejected |

A credit proof takes about 0.35 s to create and 0.75 s to verify, and is 80 KB in binary form. These forgeries are simple ones; rejecting them shows the verifier checks what it should, not that the protocols are sound.

## Configuration

| Variable | Purpose |
|---|---|
| `ZKCREDIT_ENV=production` | require API keys, a database, the statement bank's public key and the flag below; the development prover is switched off |
| `ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes` | required in production to confirm the operator knows the cryptography is unreviewed |
| `ZKCREDIT_FIP_PUBLIC_KEY` | public key of the bank that signs statements |
| `ZKCREDIT_API_KEYS` / `ZKCREDIT_KEYS_FILE` | hashed API keys with roles |
| `ZKCREDIT_DATABASE_URL` | `sqlite:///...` or `postgresql://...` |

## Limitations

- The cryptography has not been reviewed. Real use would need a cryptographer's review or a move to audited libraries such as Bulletproofs on Ristretto255.
- Range proofs are large: about 14 KB for a 64-bit proof, where Bulletproofs would need under 1 KB.
- The statement bank is simulated; there is no Account Aggregator integration, and the borrower still chooses which account and months to submit.
- Reserves are self-declared, and a bank can leave customers out of the tree. Only customers who check their inclusion proof would notice.
- The demo endpoints receive the private figures; in real use the prover would run on the borrower's device or inside the bank.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See [LICENSE](LICENSE).
