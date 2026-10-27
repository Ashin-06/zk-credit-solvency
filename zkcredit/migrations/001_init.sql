-- Every credit-proof verification the lender ran; verified means every policy predicate held. result holds the
-- verification report; the bundle itself is public (commitments and proofs, no raw figures).
CREATE TABLE credit_verifications (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    applicant_id TEXT NOT NULL,
    verified INTEGER NOT NULL,
    result TEXT NOT NULL,
    bundle TEXT NOT NULL
);
CREATE INDEX credit_verifications_applicant ON credit_verifications (applicant_id, created_at);

-- Every published proof of solvency: the root customers check their inclusion proofs against.
-- bundle is the public bundle; the sampled customer's private inclusion proof is not stored.
CREATE TABLE solvency_audits (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    bank_id TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    verified INTEGER NOT NULL,
    audit TEXT NOT NULL,
    bundle TEXT NOT NULL
);
CREATE INDEX solvency_audits_bank ON solvency_audits (bank_id, created_at);
