"""
Benchmark and Cryptographic Soundness Evaluation Suite for `zkcredit`.

Evaluates:
1. Honest Borrower Profiles (100% Completeness)
2. Ineligible / Sub-Prime Borrower Profiles (0% False Acceptance)
3. Honest Neo-Bank Merkle-Sum Proof of Solvency (100% Completeness)
4. Five Cryptographic Cheating / Forgery Attacks (0% Soundness Acceptance):
   - Attack 1: Forged Commitment Opening (violating AA homomorphic sum)
   - Attack 2: Negative Balance Injection in Merkle-Sum Tree (insolvent bank)
   - Attack 3: DTI Above Policy Cap (forged range proof on negative DTI margin)
   - Attack 4: Single-Month Overdraft Concealment (Month 7 EOD < floor)
   - Attack 5: Tampered Fiat-Shamir Transcript (mutated CDS OR-Sigma challenge)
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List

from .crypto import DEFAULT_GROUP
from .range_proof import BitOrProof, prove_range
from .solvency import (
    CustomerAccount,
    build_solvency_proof,
    verify_solvency_audit,
)
from .underwrite import (
    CASHFLOW_BIT_LENGTH,
    MonthlyFinancialRecord,
    UnderwritingPolicy,
    generate_credit_proof,
    verify_credit_proof,
)


def get_borrower_presets() -> Dict[str, Dict[str, Any]]:
    """Returns realistic 12-month Account Aggregator borrower presets."""
    return {
        "prime_salaried": {
            "applicant_id": "AA-IN-PRIME-001",
            "label": "Prime Salaried Engineer (Eligible)",
            "description": "₹1.25L/mo income, ₹30k/mo EMI (24% DTI), ₹1.14M net cashflow, min EOD >= ₹42k",
            "expected_eligible": True,
            "records": [
                MonthlyFinancialRecord(
                    month=m,
                    income=125_000 + (15_000 if m in (3, 9) else 0),
                    debt=30_000,
                    min_eod_balance=42_000 + (m * 1_500),
                )
                for m in range(1, 13)
            ],
        },
        "msme_merchant": {
            "applicant_id": "AA-IN-MSME-002",
            "label": "Profitable MSME Trader (Eligible)",
            "description": "Seasonal ₹85k–₹1.40L/mo revenue, ₹32k/mo debt (~31% DTI), min EOD >= ₹18k",
            "expected_eligible": True,
            "records": [
                MonthlyFinancialRecord(
                    month=m,
                    income=85_000 + ((m % 4) * 18_000),
                    debt=32_000,
                    min_eod_balance=18_500 + ((m % 3) * 4_000),
                )
                for m in range(1, 13)
            ],
        },
        "high_dti_subprime": {
            "applicant_id": "AA-IN-SUB-DTI-003",
            "label": "Over-Leveraged Borrower (DTI 52.5% > 40% Cap)",
            "description": "₹1.00L/mo income, ₹52.5k/mo debt (52.5% DTI exceeds 40% cap)",
            "expected_eligible": False,
            "records": [
                MonthlyFinancialRecord(
                    month=m,
                    income=100_000,
                    debt=52_500,
                    min_eod_balance=15_000,
                )
                for m in range(1, 13)
            ],
        },
        "overdraft_month7": {
            "applicant_id": "AA-IN-SUB-OD-004",
            "label": "Single-Month Overdraft Borrower (Month 7 EOD = -₹4,200)",
            "description": "Healthy income & DTI, but Month 7 suffered an EOD overdraft of -₹4,200 (< ₹5,000 floor)",
            "expected_eligible": False,
            "records": [
                MonthlyFinancialRecord(
                    month=m,
                    income=95_000,
                    debt=22_000,
                    min_eod_balance=-4_200 if m == 7 else 24_000,
                )
                for m in range(1, 13)
            ],
        },
        "low_cashflow": {
            "applicant_id": "AA-IN-SUB-CF-005",
            "label": "Insufficient Net Cashflow (₹3.12L < ₹4.80L Policy Floor)",
            "description": "₹36k/mo income, ₹10k/mo debt (27.7% DTI), annual net cashflow ₹3.12L < ₹4.80L",
            "expected_eligible": False,
            "records": [
                MonthlyFinancialRecord(
                    month=m,
                    income=36_000,
                    debt=10_000,
                    min_eod_balance=8_500,
                )
                for m in range(1, 13)
            ],
        },
    }


def get_solvency_presets() -> Dict[str, Dict[str, Any]]:
    """Returns Neo-Bank Merkle-Sum Proof of Solvency presets."""
    honest_accounts = [
        CustomerAccount("cust_aarav_01", 420_000),
        CustomerAccount("cust_diya_02", 315_000),
        CustomerAccount("cust_kabir_03", 180_000),
        CustomerAccount("cust_meera_04", 540_000),
        CustomerAccount("cust_rohan_05", 275_000),
        CustomerAccount("cust_sanya_06", 190_000),
        CustomerAccount("cust_vikram_07", 360_000),
        CustomerAccount("cust_zoya_08", 120_000),
    ]
    # Total honest liabilities = 2,400,000 INR
    return {
        "solvent_neobank": {
            "bank_id": "NEOBANK-RESERVE-SOLVENT-01",
            "label": "Solvent Neo-Bank (Reserves ₹30.0L vs Liabilities ₹24.0L)",
            "liquid_reserves": 3_000_000,
            "accounts": honest_accounts,
            "expected_solvent": True,
        },
        "undercollateralized_neobank": {
            "bank_id": "NEOBANK-UNDERCOLLATERALIZED-02",
            "label": "Insolvent Neo-Bank (Reserves ₹19.5L vs Liabilities ₹24.0L)",
            "liquid_reserves": 1_950_000,
            "accounts": honest_accounts,
            "expected_solvent": False,
        },
        "negative_leaf_injection": {
            "bank_id": "NEOBANK-NEGATIVE-INJECTION-03",
            "label": "Negative Balance Injection Attack (Phantom -₹8.0L Leaf)",
            "liquid_reserves": 1_850_000,
            "accounts": honest_accounts[:7] + [CustomerAccount("phantom_neg_08", -800_000)],
            "expected_solvent": False,
        },
    }


def run_benchmark() -> Dict[str, Any]:
    """
    Runs the full completeness, soundness, latency, and proof-size benchmark across
    honest borrowers, ineligible borrowers, solvency audits, and 5 cheating attacks.
    """
    policy = UnderwritingPolicy(
        min_annual_net_cashflow=480_000,
        max_dti_pct=40,
        min_monthly_eod_balance=5_000,
    )
    presets = get_borrower_presets()
    solvency_presets = get_solvency_presets()

    honest_cases: List[Dict[str, Any]] = []
    ineligible_cases: List[Dict[str, Any]] = []

    for key, cfg in presets.items():
        bundle = generate_credit_proof(
            applicant_id=cfg["applicant_id"],
            records=cfg["records"],
            policy=policy,
            allow_forged=not cfg["expected_eligible"],
        )
        ver = verify_credit_proof(bundle, expected_policy=policy)
        entry = {
            "preset_key": key,
            "applicant_id": cfg["applicant_id"],
            "label": cfg["label"],
            "expected_eligible": cfg["expected_eligible"],
            "verified": ver.verified,
            "homomorphic_consistency_ok": ver.homomorphic_consistency_ok,
            "net_cashflow_ok": ver.net_cashflow_ok,
            "dti_ok": ver.dti_ok,
            "eod_balances_ok": ver.eod_balances_ok,
            "failed_months": ver.failed_months,
            "proof_size_bytes": bundle.total_proof_bytes(),
            "prove_ms": round(bundle.generation_ms, 2),
            "verify_ms": round(ver.verification_ms, 2),
            "reason": ver.reason,
        }
        if cfg["expected_eligible"]:
            honest_cases.append(entry)
        else:
            ineligible_cases.append(entry)

    # Honest Solvency Audit case
    solvent_cfg = solvency_presets["solvent_neobank"]
    solvent_bundle = build_solvency_proof(
        bank_id=solvent_cfg["bank_id"],
        accounts=solvent_cfg["accounts"],
        liquid_reserves=solvent_cfg["liquid_reserves"],
        sample_user_index=0,
        allow_forged=False,
    )
    solvent_audit = verify_solvency_audit(solvent_bundle)
    honest_cases.append(
        {
            "preset_key": "solvent_neobank",
            "applicant_id": solvent_cfg["bank_id"],
            "label": solvent_cfg["label"],
            "expected_eligible": True,
            "verified": solvent_audit.verified,
            "homomorphic_consistency_ok": solvent_audit.merkle_sum_tree_consistent,
            "net_cashflow_ok": solvent_audit.reserve_surplus_verified,
            "dti_ok": solvent_audit.all_leaves_nonnegative,
            "eod_balances_ok": solvent_audit.sample_inclusion_verified,
            "failed_months": solvent_audit.invalid_leaf_indices,
            "proof_size_bytes": solvent_bundle.total_proof_bytes(),
            "prove_ms": round(solvent_bundle.generation_ms, 2),
            "verify_ms": round(solvent_audit.verification_ms, 2),
            "reason": solvent_audit.reason,
        }
    )

    # -------------------------------------------------------------------------
    # 5 Cryptographic Cheating / Soundness Attacks
    # -------------------------------------------------------------------------
    cheating_attacks: List[Dict[str, Any]] = []

    # Attack 1: Forged Commitment Opening (substituting higher net cashflow commitment)
    low_cf_records = presets["low_cashflow"]["records"]
    low_cf_bundle = generate_credit_proof(
        applicant_id="ATK-01-FORGED-OPENING",
        records=low_cf_records,
        policy=policy,
        allow_forged=True,
    )
    # Attacker replaces c_net_cashflow and net_cashflow_proof with a valid commitment to ₹6,50,000
    fake_c_net, fake_r_net = DEFAULT_GROUP.commit(650_000)
    fake_net_proof = prove_range(
        value=650_000,
        blinding=fake_r_net,
        commitment=fake_c_net,
        lower_bound=policy.min_annual_net_cashflow,
        bit_length=CASHFLOW_BIT_LENGTH,
        context=f"ATK-01-FORGED-OPENING|net_cashflow|{policy.min_annual_net_cashflow}",
    )
    forged_opening_bundle = replace(
        low_cf_bundle,
        c_net_cashflow=fake_c_net,
        net_cashflow_proof=fake_net_proof,
    )
    atk1_res = verify_credit_proof(forged_opening_bundle, expected_policy=policy)
    cheating_attacks.append(
        {
            "attack_id": "ATK-01",
            "name": "Forged Commitment Opening (Homomorphic Sum Bypass)",
            "target": "Underwriting Net Cashflow Commitment",
            "accepted": atk1_res.verified,
            "rejected": not atk1_res.verified,
            "verify_ms": round(atk1_res.verification_ms, 2),
            "detection_reason": atk1_res.reason,
        }
    )

    # Attack 2: Negative Balance Injection in Merkle-Sum Commitment Tree
    neg_cfg = solvency_presets["negative_leaf_injection"]
    neg_bundle = build_solvency_proof(
        bank_id=neg_cfg["bank_id"],
        accounts=neg_cfg["accounts"],
        liquid_reserves=neg_cfg["liquid_reserves"],
        sample_user_index=6,  # Sibling of leaf 7 (the negative leaf!)
        allow_forged=True,
    )
    atk2_res = verify_solvency_audit(neg_bundle)
    cheating_attacks.append(
        {
            "attack_id": "ATK-02",
            "name": "Negative Balance Leaf Injection in Merkle-Sum Tree",
            "target": "Neo-Bank Proof of Solvency (Leaf #7 = -₹8,00,000)",
            "accepted": atk2_res.verified,
            "rejected": not atk2_res.verified,
            "verify_ms": round(atk2_res.verification_ms, 2),
            "detection_reason": atk2_res.reason,
        }
    )

    # Attack 3: DTI Above Cap (52.5% DTI forged range proof on negative DTI margin)
    dti_bundle = generate_credit_proof(
        applicant_id="ATK-03-DTI-OVER-CAP",
        records=presets["high_dti_subprime"]["records"],
        policy=policy,
        allow_forged=True,
    )
    atk3_res = verify_credit_proof(dti_bundle, expected_policy=policy)
    cheating_attacks.append(
        {
            "attack_id": "ATK-03",
            "name": "DTI Ratio Above Cap (52.5% vs 40% Policy Cap)",
            "target": "Homomorphic Linear Combination 40*sum(I) - 100*sum(D) >= 0",
            "accepted": atk3_res.verified,
            "rejected": not atk3_res.verified,
            "verify_ms": round(atk3_res.verification_ms, 2),
            "detection_reason": atk3_res.reason,
        }
    )

    # Attack 4: Overdraft Month Concealment (Month 7 EOD = -₹4,200 < ₹5,000 floor)
    od_bundle = generate_credit_proof(
        applicant_id="ATK-04-OVERDRAFT-MONTH7",
        records=presets["overdraft_month7"]["records"],
        policy=policy,
        allow_forged=True,
    )
    atk4_res = verify_credit_proof(od_bundle, expected_policy=policy)
    cheating_attacks.append(
        {
            "attack_id": "ATK-04",
            "name": "Single-Month Overdraft Concealment (Month 7 EOD = -₹4,200)",
            "target": "Month 7 Minimum EOD Balance Range Proof",
            "accepted": atk4_res.verified,
            "rejected": not atk4_res.verified,
            "verify_ms": round(atk4_res.verification_ms, 2),
            "detection_reason": atk4_res.reason,
        }
    )

    # Attack 5: Tampered Fiat-Shamir Transcript (mutating CDS OR-Sigma response s0)
    valid_bundle = generate_credit_proof(
        applicant_id="ATK-05-FIAT-SHAMIR-TAMPER",
        records=presets["prime_salaried"]["records"],
        policy=policy,
        allow_forged=False,
    )
    orig_bp = valid_bundle.dti_proof.bit_proofs[0]
    tampered_bp = BitOrProof(
        bit_index=orig_bp.bit_index,
        bit_commitment=orig_bp.bit_commitment,
        t0=orig_bp.t0,
        t1=orig_bp.t1,
        e0=orig_bp.e0,
        e1=orig_bp.e1,
        s0=(orig_bp.s0 + 1) % DEFAULT_GROUP.q,
        s1=orig_bp.s1,
    )
    tampered_dti_proof = replace(
        valid_bundle.dti_proof,
        bit_proofs=[tampered_bp] + valid_bundle.dti_proof.bit_proofs[1:],
    )
    tampered_bundle = replace(valid_bundle, dti_proof=tampered_dti_proof)
    atk5_res = verify_credit_proof(tampered_bundle, expected_policy=policy)
    cheating_attacks.append(
        {
            "attack_id": "ATK-05",
            "name": "Tampered Fiat-Shamir Transcript (Mutated CDS OR Response)",
            "target": "DTI Bit-0 1-of-2 CDS OR-Sigma Schnorr Equation",
            "accepted": atk5_res.verified,
            "rejected": not atk5_res.verified,
            "verify_ms": round(atk5_res.verification_ms, 2),
            "detection_reason": atk5_res.reason,
        }
    )

    honest_passed = sum(1 for c in honest_cases if c["verified"])
    ineligible_rejected = sum(1 for c in ineligible_cases if not c["verified"])
    attacks_rejected = sum(1 for a in cheating_attacks if a["rejected"])

    all_prove_ms = [c["prove_ms"] for c in honest_cases + ineligible_cases]
    all_verify_ms = [c["verify_ms"] for c in honest_cases + ineligible_cases]

    return {
        "group_parameters": {
            "prime_bits": DEFAULT_GROUP.p.bit_length(),
            "SafePrime_p_prefix": hex(DEFAULT_GROUP.p)[:26] + "...",
            "SubgroupOrder_q_bits": DEFAULT_GROUP.q.bit_length(),
            "generator_g_prefix": hex(DEFAULT_GROUP.g)[:22] + "...",
            "generator_h_prefix": hex(DEFAULT_GROUP.h)[:22] + "...",
        },
        "summary": {
            "honest_total": len(honest_cases),
            "honest_verified": honest_passed,
            "completeness_rate": round(honest_passed / len(honest_cases), 4),
            "ineligible_total": len(ineligible_cases),
            "ineligible_rejected": ineligible_rejected,
            "cheating_attacks_total": len(cheating_attacks),
            "cheating_attacks_rejected": attacks_rejected,
            "cheating_acceptance_rate": round(
                (len(cheating_attacks) - attacks_rejected) / len(cheating_attacks), 4
            ),
            "soundness_rejection_rate": round(attacks_rejected / len(cheating_attacks), 4),
            "avg_prove_ms": round(sum(all_prove_ms) / len(all_prove_ms), 2),
            "avg_verify_ms": round(sum(all_verify_ms) / len(all_verify_ms), 2),
            "credit_proof_size_bytes": honest_cases[0]["proof_size_bytes"],
            "solvency_proof_size_bytes": honest_cases[-1]["proof_size_bytes"],
        },
        "honest_cases": honest_cases,
        "ineligible_cases": ineligible_cases,
        "cheating_attacks": cheating_attacks,
    }


def format_benchmark_table(report: Dict[str, Any]) -> str:
    """Formats the benchmark report as a clean ASCII summary table for CLI output."""
    lines: List[str] = []
    s = report["summary"]
    gp = report["group_parameters"]
    lines.append("=" * 92)
    lines.append(" ZKCREDIT: ZERO-KNOWLEDGE CREDIT UNDERWRITING & PROOF-OF-SOLVENCY BENCHMARK ")
    lines.append("=" * 92)
    lines.append(
        f" Group: {gp['prime_bits']}-bit Safe Prime p = 2q+1 | Order q: {gp['SubgroupOrder_q_bits']} bits"
    )
    lines.append(
        f" Completeness (Honest): {s['honest_verified']}/{s['honest_total']} ({s['completeness_rate']*100:.1f}%) | "
        f"Soundness Rejection (Attacks): {s['cheating_attacks_rejected']}/{s['cheating_attacks_total']} "
        f"({s['soundness_rejection_rate']*100:.1f}%)"
    )
    lines.append(
        f" Avg Prove Latency: {s['avg_prove_ms']:.2f} ms | Avg Verify Latency: {s['avg_verify_ms']:.2f} ms | "
        f"Credit Proof Size: {s['credit_proof_size_bytes']:,} B"
    )
    lines.append("-" * 92)
    lines.append(" [1] HONEST & INELIGIBLE PROFILES")
    lines.append(f" {'ID':<28} {'Expected':<10} {'Verified':<10} {'Size (B)':<10} {'Prove(ms)':<10} {'Verify(ms)':<10}")
    lines.append(" " + "-" * 88)
    for c in report["honest_cases"] + report["ineligible_cases"]:
        lines.append(
            f" {c['applicant_id']:<28} {str(c['expected_eligible']):<10} {str(c['verified']):<10} "
            f"{c['proof_size_bytes']:<10} {c['prove_ms']:<10.2f} {c['verify_ms']:<10.2f}"
        )
    lines.append("-" * 92)
    lines.append(" [2] CRYPTOGRAPHIC CHEATING & FORGERY ATTACKS (SOUNDNESS SUITE)")
    lines.append(f" {'Code':<8} {'Attack Name':<52} {'Accepted':<10} {'Verify(ms)':<10}")
    lines.append(" " + "-" * 88)
    for a in report["cheating_attacks"]:
        lines.append(
            f" {a['attack_id']:<8} {a['name']:<52} {str(a['accepted']):<10} {a['verify_ms']:<10.2f}"
        )
        lines.append(f"          -> Caught: {a['detection_reason']}")
    lines.append("=" * 92)
    return "\n".join(lines)
