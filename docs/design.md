# Design

## Group

Commitments live in the prime-order subgroup of Ed25519 (order L ≈ 2^252), using libsodium's point arithmetic through PyNaCl. g is the standard base point. h is derived with a SHA-512 try-and-increment hash, so nobody knows log_g(h). PyNaCl's `is_valid_point` does not check subgroup membership, so every received point is also checked with L·P = 0. The tests check base-point multiplication against RFC 8032 test 1.

## Pedersen commitments

C(v, r) = v·g + r·h. Commitments can be added, which lets the verifier rebuild annual totals, the debt-to-income margin `max_dti_pct·ΣI − 100·ΣD`, tree nodes and the reserve surplus from the published commitments alone.

## Range proofs

`range_proof.py` proves v − τ ∈ [0, 2^k). The prover commits to each bit and gives a Cramer–Damgård–Schoenmakers 1-of-2 OR proof that each bit commitment opens to 0 or 1, and the verifier checks that Σ 2^j·C_j equals the shifted commitment. Challenges are Fiat-Shamir SHA-512 hashes over typed, length-prefixed fields: the generators, the statement, the announcements and a context string with the applicant or bank ID. k is capped at 64, because with 253 bits a negative value mod L could be written as valid bits; a test covers that forgery.

## Credit underwriting

`underwrite.py`. The account-holding bank (the FIP, in Account Aggregator terms) commits to each month's income, debt and minimum end-of-day balance, and signs the applicant ID plus all 36 commitments with Ed25519. The lender checks that signature against an FIP key it already trusts, rebuilds the aggregates and verifies 14 range proofs: net cashflow (28 bits), debt-to-income margin (32 bits) and 12 monthly balance floors (24 bits each). Without the signature the bundle is rejected, because a borrower could otherwise commit to any numbers.

## Proof of solvency

`solvency.py`. Each leaf commits to a balance in [0, 2^28) and is labelled with H(nonce ‖ user ID), where the nonce is random per customer and given only to that customer. Internal nodes add their children's commitments and hash them. The bank commits to its reserves R and proves R − L ≥ 0 on C_reserves − C_root (a 64-bit range). The auditor checks every leaf proof, rebuilds the tree and checks the surplus proof. Each customer's inclusion proof (their balance, blinding and nonce, plus the sibling path with a non-negativity proof per sibling) is given only to them and kept out of the published bundle.

## Size limits

Range proofs cost 224 bytes per bit. The bit lengths set these ceilings, all constants in the code:

- a minimum monthly balance more than about ₹1.67 crore above the floor;
- net cashflow more than about ₹26.8 crore above the floor;
- a debt-to-income margin above about ₹429 crore;
- a single customer balance above about ₹26.8 crore.
