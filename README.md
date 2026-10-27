# ZK Credit & Proof of Solvency (`zkcredit`)

Two zero-knowledge checks a lender or regulator might want without seeing the underlying numbers:

1. **Credit underwriting.** A borrower proves three policy predicates over 12 months of bank statements (annual net cashflow above a floor, debt-to-income under a cap, no month below a minimum end-of-day balance). The lender sees only Pedersen commitments, range proofs and the statement provider's signature.
2. **Neo-bank proof of solvency.** A bank publishes a Merkle-sum tree of committed customer balances and proves its committed reserves cover the total. Each customer can check that their own balance is in the tree.

> **Reference implementation, not production cryptography.** The group arithmetic comes from libsodium, but the commitment scheme, range proofs, Fiat-Shamir transcripts and tree are hand-written and have not been independently reviewed. Scalar arithmetic uses Python integers, which are not constant-time. Treat it as a readable model of the protocols, not something to protect real money with.

## How it works

**Group.** Commitments live in the prime-order subgroup of Ed25519 (order L ≈ 2^252), using libsodium's point arithmetic through PyNaCl. g is the standard base point. h comes from a SHA-512 try-and-increment hash, so nobody knows log_g(h). PyNaCl 1.5's `is_valid_point` does not check subgroup membership, so every received point is also checked with L·P = 0. The tests check base-point multiplication against RFC 8032 test 1.

**Pedersen commitments.** C(v, r) = v·g + r·h, additively homomorphic. That is what lets the verifier rebuild annual totals, the DTI margin `max_dti_pct·ΣI − 100·ΣD`, tree nodes and the reserve surplus from the published commitments alone.

**Range proofs** (`range_proof.py`). To prove v − τ ∈ [0, 2^k), the prover commits to each bit and gives a Cramer–Damgård–Schoenmakers 1-of-2 OR proof that each bit commitment opens to 0 or 1. The verifier checks that Σ 2^j·C_j equals the shifted commitment. Challenges are Fiat-Shamir SHA-512 hashes over typed, length-prefixed fields: the generators, the statement, the announcements and a context string with the applicant or bank ID. k is capped at 64; with 253 bits, a negative value mod L can be written as genuine bits (there is a test for that forgery).

**Underwriting** (`underwrite.py`). The FIP (the bank holding the account) commits to each month's income, debt and minimum EOD balance and signs the applicant ID plus all 36 commitments with Ed25519. The lender checks that signature against an FIP key it already trusts, rebuilds the aggregates homomorphically and verifies 14 range proofs: net cashflow (28 bits), DTI margin (32 bits) and 12 EOD floors (24 bits each). Without the signature the bundle is rejected, because a borrower could otherwise commit to any numbers they like.

**Solvency** (`solvency.py`). Each leaf commits to a balance in [0, 2^28) and is labelled with H(nonce ‖ user ID); the nonce is random per customer and given only to that customer. Internal nodes add their children's commitments and hash them. The bank commits to reserves R and proves R − L ≥ 0 on C_reserves − C_root (64-bit range). The auditor checks every leaf proof, rebuilds the tree and checks the surplus proof. A customer's inclusion proof (their balance, blinding and nonce, plus the sibling path with a 64-bit non-negativity proof per sibling) is private to them and kept out of the published bundle.

## Results

`python -m zkcredit bench` uses hand-written preset profiles, not real statements:

| Case | Expected | Result |
|---|---|---|
| Prime salaried, profitable MSME | eligible | verified |
| Solvent neo-bank (8 customers, ₹30L reserves vs ₹24L liabilities) | solvent | verified |
| DTI 52.5% vs 40% cap, month-7 overdraft, cashflow below floor | ineligible | rejected |
| ATK-01 swap in a commitment to a higher net cashflow | reject | rejected (aggregate mismatch) |
| ATK-02 negative-balance leaf to hide liabilities | reject | rejected (leaf proof and inclusion path) |
| ATK-03 / ATK-04 forged range proofs for the DTI and overdraft cases | reject | rejected |
| ATK-05 one response scalar changed | reject | rejected |
| ATK-06 borrower commits to invented figures and signs with their own key | reject | rejected (not the FIP's signature) |

On this machine one credit bundle takes about 0.35 s to prove and 0.75 s to verify. It is 80,332 bytes in compact binary form (about 200 KB as the JSON the API returns). The 8-customer solvency bundle is 65,786 bytes. Timings vary by about ±15% between runs.

The attack cases are fixed, fairly naive forgeries. Rejecting them shows the verifier checks what it should. It is not evidence of soundness, which rests on the standard security arguments for these protocols and on the code matching them.

## Run it

```bash
pip install -r requirements.txt           # or: pip install -r requirements-dev.lock && pip install -e .
python -m pytest -q                       # 21 tests
python -m zkcredit bench                  # the table above
python -m zkcredit serve                  # API + console at http://127.0.0.1:8012 (demo FIP key, open, loopback only)
docker build -t zk-credit-solvency .      # production image; see docs/runbook.md
```

| Endpoint | |
|---|---|
| `GET /params` | group parameters, the FIP public key in use, and the review status of the cryptography |
| `GET /presets` | preset borrowers and banks |
| `POST /underwrite/prove` | build and check a credit bundle; the server plays FIP and borrower, so this is development only |
| `POST /underwrite/verify` | verify a bundle against the pinned FIP key; every verification is recorded |
| `GET /underwrite/verifications[/{id}]` | recorded verifications |
| `POST /solvency/audit` | build, audit and publish a solvency bundle; the sampled customer's inclusion proof comes back as a separate field and is not stored |
| `GET /solvency/audits[/{id}]` | published proofs of solvency and the roots customers check against |
| `GET /bench` | the benchmark (admin only: slow) |
| `GET /healthz`, `/readyz`, `/metrics` | liveness, readiness, Prometheus metrics |

Each caller gets an API key with a role: `lender` verifies and reads, `bank` publishes proofs of solvency and reads, `viewer` reads, `applicant` may use the development-only prover, and `monitor` scrapes metrics. Make one with `python -m zkcredit.ops keygen` and list its hash in `ZKCREDIT_API_KEYS` or `ZKCREDIT_KEYS_FILE`. Without keys the server runs open and refuses to bind a non-loopback address. Requests are capped at 1 MB and 64 accounts.

**Production mode** (`ZKCREDIT_ENV=production`) has these requirements:
- It refuses to start unless `ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes`. That flag says the operator knows the protocols have not been reviewed (see the note at the top), and the service logs the same warning on every start.
- It needs the FIP's Ed25519 public key in `ZKCREDIT_FIP_PUBLIC_KEY`. It holds no FIP signing key, so `/underwrite/prove` is refused, as are the forged-proof demos (`allow_forged`).
- It also needs hashed keys and a database.

Settings, backups and incident steps are in [docs/runbook.md](docs/runbook.md).

## Limits

- **Not reviewed.** See the note at the top. Before relying on any of it you would want an independent cryptographic review, or a move to an audited library (Bulletproofs or another vetted range-proof implementation, a Ristretto255 group).
- **Range proofs are big and slow.** Bit-by-bit OR proofs cost 224 bytes per bit. Bulletproofs would shrink a 64-bit proof from about 14 KB to under 1 KB.
- **Bit-length ceilings.** A borrower whose minimum EOD balance is more than about ₹1.67 crore above the floor, whose net cashflow exceeds the floor by more than about ₹26.8 crore, or whose DTI margin (`max_dti_pct × annual income − 100 × annual debt`) passes about ₹429 crore cannot produce a proof. A single bank customer can hold at most about ₹26.8 crore. All of these are constants in the code.
- **The FIP integration is simulated.** The demo generates a fresh FIP key on each start and one process plays FIP, borrower and lender. There is no Account Aggregator / ReBIT integration and no FIP key distribution, and the borrower still chooses which account and which 12 months to submit.
- **Reserves are self-declared.** The solvency proof shows that committed reserves cover committed liabilities. Nothing ties the reserve commitment to real assets; that needs a custodian or auditor attestation.
- **Liabilities can be left out.** As with any Merkle-sum proof of liabilities, a bank can omit customers. Only customers who check their inclusion proofs would notice. The bundle also reveals the customer count.
- **The demo server sees raw figures.** `/underwrite/prove` and `/solvency/audit` take the private inputs, which is fine for a demo. In real use the prover runs on the borrower's device or inside the bank.
- **Thin operations story.** Verifications and published proofs of solvency are stored, but there is no FIP key distribution or rotation protocol, and TLS is left to the ingress.

## Production readiness

**In place** (see [docs/runbook.md](docs/runbook.md) and [docs/threat-model.md](docs/threat-model.md)):
- Pinned dependencies (`requirements.lock`), `pyproject.toml`, a container image that runs as a non-root user with a health check, and CI (ruff, bandit, pip-audit, tests with coverage).
- Production mode that refuses to start without the explicit unreviewed-cryptography acknowledgement, the FIP's public key, hashed per-client API keys and a database. It holds no signing key and disables the demo prover and forged-proof demos.
- Roles on keys, per-client rate limits, a body cap, security headers, CORS only for listed origins, and errors that don't echo input.
- Recorded credit verifications and published proofs of solvency in SQLite or Postgres, with numbered migrations.
- JSON logs with request IDs, `/healthz`, `/readyz`, and Prometheus metrics for verified and rejected proofs.

**Still needed before any real use**, none of which code can supply:
- **A cryptographer's review** of the commitment scheme, range proofs, Fiat-Shamir transcripts and Merkle-sum tree, or a move to audited libraries (Bulletproofs, Ristretto255). This is the first requirement, ahead of everything below.
- An independent security review and penetration test.
- Validation on real Account Aggregator data. Every profile here is hand-written.
- RBI sign-off (Account Aggregator framework, digital lending directions) and DPDP Act 2023 consent handling.
- Real integrations: the Account Aggregator / ReBIT flows with FIP key distribution, the lender's loan origination system, and a custodian or auditor attestation for reserves.
- The FIP's signing keys in an HSM, and an on-call team with SLOs.
