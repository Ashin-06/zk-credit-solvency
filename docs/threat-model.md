# Threat model

What zkcredit protects, from whom, and what is still open. Written for the 1.0.0 code; nobody
independent has reviewed it, and **the cryptography is hand-written and unreviewed**.

## What it protects

| Asset | Where it lives |
|---|---|
| A borrower's monthly income, debt and balances | never sent to the lender: only commitments and proofs |
| Customers' balances in a proof of solvency | committed in leaves; each customer gets a private inclusion proof |
| The FIP's attestation | Ed25519 signature over the applicant ID and all monthly commitments |
| Recorded verifications and published solvency roots | `credit_verifications`, `solvency_audits` tables |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

## Trust boundaries

```
FIP ──(signs commitments)──► borrower ──(bundle)──► lender: zkcredit /underwrite/verify
bank ──► zkcredit /solvency/audit ──(publishes root)──► customers check inclusion
```

1. **FIP → lender.** The lender trusts only the pinned FIP public key, never a key inside a bundle.
2. **Prover → verifier.** Everything in a bundle is untrusted until the proofs check out.
3. **API → database.** Stores public material only (commitments, proofs, reports).

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| A borrower proves a false predicate | Range proofs, OR-proofs, homomorphic checks; FIP signature on the commitments | **Soundness rests on unreviewed hand-written code.** Production refuses to start without an explicit acknowledgement. |
| A borrower invents figures and signs them | Signature must verify against the pinned FIP key | A leaked FIP key forges anything; the borrower still picks which accounts to include |
| Modular wrap-around or torsion tricks | Bit-length caps; explicit prime-order subgroup check on every point | Same caveat: unreviewed |
| A bank hides liabilities | Non-negative leaf proofs; Merkle-sum consistency; customers check inclusion | Omitted customers are invisible unless they check; reserves are self-declared |
| Learning a committed value from a bundle | Pedersen hiding; random blindings from the OS | Unreviewed; the customer count and tree size are public |
| The server sees private inputs | Production disables the demo prover; solvency proving runs where the bank's data already is | The bank's own instance sees its customers' balances (it holds them anyway) |
| Flooding or CPU exhaustion (proofs are slow) | 1 MB body cap, 64 accounts per audit, per-client rate limit, `/bench` admin-only | Rate limit is per process |
| Error messages leak data | Validation errors and bad bundles return no input; 500s only a request ID | — |

## Not covered

- The Account Aggregator consent flow and FIP key distribution.
- Proof of reserves (assets): needs a custodian or auditor attestation.
- TLS (terminate it at the ingress).
