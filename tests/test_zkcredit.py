"""
Comprehensive test suite for `zkcredit` (Project 12: Zero-Knowledge Credit Underwriting
& Cryptographic Proof-of-Solvency Engine).
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from zkcredit.api import app
from zkcredit.bench import get_borrower_presets, get_solvency_presets, run_benchmark
from zkcredit.crypto import (
    DEFAULT_GROUP,
    prove_equality,
    prove_opening,
    prove_zero_commitment,
    verify_equality,
    verify_opening_proof,
    verify_zero_commitment,
)
from zkcredit.range_proof import (
    BitOrProof,
    forge_range_proof_attempt,
    prove_range,
    verify_range,
)
from zkcredit.solvency import (
    CustomerAccount,
    build_solvency_proof,
    verify_customer_inclusion,
    verify_solvency_audit,
)
from zkcredit.underwrite import (
    CreditProofBundle,
    MonthlyFinancialRecord,
    UnderwritingPolicy,
    generate_credit_proof,
    verify_credit_proof,
)


def test_safe_prime_group_and_homomorphism() -> None:
    g = DEFAULT_GROUP
    assert g.q.bit_length() == 253
    assert g.g != g.h
    assert g.is_valid_element(g.g)
    assert g.is_valid_element(g.h)

    v1, v2 = 125_000, 48_500
    c1, r1 = g.commit(v1)
    c2, r2 = g.commit(v2)

    # Homomorphic addition: C(v1, r1) * C(v2, r2) == C(v1 + v2, r1 + r2)
    c_sum = g.add_commitments(c1, c2)
    assert g.verify_opening(c_sum, v1 + v2, (r1 + r2) % g.q)

    # Homomorphic subtraction: C(v1, r1) * C(v2, r2)^(-1) == C(v1 - v2, r1 - r2)
    c_diff = g.sub_commitments(c1, c2)
    assert g.verify_opening(c_diff, v1 - v2, (r1 - r2) % g.q)

    # Homomorphic linear combination: 40 * v1 - 100 * v2
    c_lin = g.sub_commitments(g.mul(c1, 40), g.mul(c2, 100))
    assert g.verify_opening(c_lin, 40 * v1 - 100 * v2, (40 * r1 - 100 * r2) % g.q)


def test_schnorr_opening_zero_and_equality_proofs() -> None:
    g = DEFAULT_GROUP
    c1, r1 = g.commit(350_000)
    c2, r2 = g.commit(350_000)
    c_other, _ = g.commit(350_001)

    op = prove_opening(350_000, r1, commitment=c1, context="test-open")
    assert verify_opening_proof(op, expected_commitment=c1, context="test-open")
    assert not verify_opening_proof(op, expected_commitment=c_other, context="test-open")
    assert not verify_opening_proof(op, expected_commitment=c1, context="wrong-ctx")

    c_zero, r_zero = g.commit(0)
    zp = prove_zero_commitment(r_zero, commitment=c_zero, context="test-zero")
    assert verify_zero_commitment(zp, expected_commitment=c_zero, context="test-zero")
    assert not verify_zero_commitment(zp, expected_commitment=c1, context="test-zero")

    eq_proof = prove_equality(350_000, c1, r1, c2, r2, context="test-eq")
    assert verify_equality(c1, c2, eq_proof, context="test-eq")
    assert not verify_equality(c1, c_other, eq_proof, context="test-eq")


def test_cds_bit_range_proof_completeness_and_soundness() -> None:
    # Lower bound boundary: v == lower_bound
    c_low, r_low = DEFAULT_GROUP.commit(5_000)
    p_low = prove_range(5_000, r_low, commitment=c_low, lower_bound=5_000, bit_length=16, context="low")
    assert verify_range(p_low, expected_commitment=c_low, expected_lower_bound=5_000, expected_bit_length=16, context="low")

    # Upper bound boundary: v == lower_bound + 2^16 - 1
    v_max = 5_000 + (1 << 16) - 1
    c_max, r_max = DEFAULT_GROUP.commit(v_max)
    p_max = prove_range(v_max, r_max, commitment=c_max, lower_bound=5_000, bit_length=16, context="max")
    assert verify_range(p_max, expected_commitment=c_max, expected_lower_bound=5_000, expected_bit_length=16, context="max")

    # Honest prover rejects out-of-range witness
    with pytest.raises(ValueError):
        prove_range(4_999, r_low, lower_bound=5_000, bit_length=16)

    # Forged range proof strategies must be rejected by verifier
    _, r_neg = DEFAULT_GROUP.commit(4_200)
    forged_wrap = forge_range_proof_attempt(
        actual_value=4_200,
        blinding=r_neg,
        lower_bound=5_000,
        bit_length=16,
        context="forged",
        strategy="modular_wrap",
    )
    assert not verify_range(forged_wrap, expected_lower_bound=5_000, expected_bit_length=16, context="forged")

    forged_bit = forge_range_proof_attempt(
        actual_value=4_200,
        blinding=r_neg,
        lower_bound=5_000,
        bit_length=16,
        context="forged-bit",
        strategy="fake_bit_opening",
    )
    assert not verify_range(forged_bit, expected_lower_bound=5_000, expected_bit_length=16, context="forged-bit")


def test_underwriting_honest_and_ineligible_profiles() -> None:
    policy = UnderwritingPolicy(
        min_annual_net_cashflow=480_000,
        max_dti_pct=40,
        min_monthly_eod_balance=5_000,
    )
    presets = get_borrower_presets()

    # Honest Prime Salaried
    prime_bundle = generate_credit_proof(
        applicant_id="TEST-PRIME",
        records=presets["prime_salaried"]["records"],
        policy=policy,
    )
    prime_res = verify_credit_proof(prime_bundle, expected_policy=policy)
    assert prime_res.verified is True
    assert prime_res.homomorphic_consistency_ok is True
    assert prime_res.net_cashflow_ok is True
    assert prime_res.dti_ok is True
    assert prime_res.eod_balances_ok is True
    assert prime_res.failed_months == []

    # Roundtrip dictionary serialization
    rehydrated = CreditProofBundle.from_dict(prime_bundle.to_dict())
    assert verify_credit_proof(rehydrated, expected_policy=policy).verified is True

    # Overdraft in Month 7 fails only Month 7 EOD predicate
    od_bundle = generate_credit_proof(
        applicant_id="TEST-OD",
        records=presets["overdraft_month7"]["records"],
        policy=policy,
        allow_forged=True,
    )
    od_res = verify_credit_proof(od_bundle, expected_policy=policy)
    assert od_res.verified is False
    assert od_res.net_cashflow_ok is True
    assert od_res.dti_ok is True
    assert od_res.eod_balances_ok is False
    assert od_res.failed_months == [7]


def test_merkle_sum_solvency_and_inclusion() -> None:
    s_presets = get_solvency_presets()

    # 1. Solvent Neo-Bank
    sol_cfg = s_presets["solvent_neobank"]
    sol_bundle = build_solvency_proof(
        bank_id=sol_cfg["bank_id"],
        accounts=sol_cfg["accounts"],
        liquid_reserves=sol_cfg["liquid_reserves"],
        sample_user_index=3,
    )
    sol_audit = verify_solvency_audit(sol_bundle)
    assert sol_audit.verified is True
    assert sol_audit.all_leaves_nonnegative is True
    assert sol_audit.merkle_sum_tree_consistent is True
    assert sol_audit.reserve_surplus_verified is True
    assert sol_audit.sample_inclusion_verified is True
    assert len(sol_bundle.sample_inclusion_proof.path) == 3  # log2(8) = 3

    # 2. Negative Balance Injection Attack
    neg_cfg = s_presets["negative_leaf_injection"]
    neg_bundle = build_solvency_proof(
        bank_id=neg_cfg["bank_id"],
        accounts=neg_cfg["accounts"],
        liquid_reserves=neg_cfg["liquid_reserves"],
        sample_user_index=6,
        allow_forged=True,
    )
    neg_audit = verify_solvency_audit(neg_bundle)
    assert neg_audit.verified is False
    assert neg_audit.all_leaves_nonnegative is False
    assert 7 in neg_audit.invalid_leaf_indices
    # Sibling of leaf 6 is leaf 7 (negative), so customer 6's O(log N) inclusion check also catches it!
    assert neg_audit.sample_inclusion_verified is False


def test_benchmark_100pct_completeness_and_0pct_cheating() -> None:
    report = run_benchmark()
    summary = report["summary"]
    assert summary["completeness_rate"] == 1.0
    assert summary["cheating_acceptance_rate"] == 0.0
    assert summary["soundness_rejection_rate"] == 1.0
    assert summary["cheating_attacks_total"] == 5
    assert summary["cheating_attacks_rejected"] == 5


def test_fastapi_endpoints() -> None:
    client = TestClient(app)

    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "ZKCredit" in r_root.text

    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["group"]["name"] == "ed25519"

    r_prove = client.post("/underwrite/prove", json={"preset_key": "prime_salaried"})
    assert r_prove.status_code == 200
    prove_data = r_prove.json()
    assert prove_data["verification"]["verified"] is True

    r_verify = client.post("/underwrite/verify", json={"bundle": prove_data["bundle"]})
    assert r_verify.status_code == 200
    assert r_verify.json()["verified"] is True

    r_sol = client.post("/solvency/audit", json={"preset_key": "solvent_neobank"})
    assert r_sol.status_code == 200
    assert r_sol.json()["audit"]["verified"] is True

    r_bench = client.get("/bench")
    assert r_bench.status_code == 200
    assert r_bench.json()["summary"]["completeness_rate"] == 1.0
    assert r_bench.json()["summary"]["cheating_acceptance_rate"] == 0.0
