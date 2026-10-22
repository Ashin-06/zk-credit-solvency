"""
Zero-Knowledge Credit Underwriting Engine for Open Banking (Account Aggregator).

A borrower holds 12 months of FIP/Account-Aggregator attested statements:
  - Monthly Income I_m
  - Monthly Debt/EMI Obligations D_m
  - Monthly Minimum End-of-Day (EOD) Balance B_m

The borrower generates a `CreditProofBundle` containing ONLY Pedersen commitments
and zero-knowledge range proofs that attest to three credit underwriting predicates
without revealing any raw Rupee figures:
  1. Annual Net Disposable Cashflow: sum_{m=1}^{12} (I_m - D_m) >= min_annual_net_cashflow
  2. Debt-to-Income Ratio Cap:       100 * sum(D_m) <= max_dti_pct * sum(I_m)
                                     <=> max_dti_pct * sum(I_m) - 100 * sum(D_m) >= 0
  3. Zero Overdraft / Min EOD Floor: B_m >= min_monthly_eod_balance for all m in 1..12
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from .crypto import DEFAULT_GROUP, PedersenGroup
from .range_proof import (
    RangeProof,
    forge_range_proof_attempt,
    prove_range,
    verify_range,
)

CASHFLOW_BIT_LENGTH = 28  # Covers up to ~2.68 Crore INR net cashflow
DTI_MARGIN_BIT_LENGTH = 32  # Covers 100 * income up to ~4.29 Crore INR
BALANCE_BIT_LENGTH = 24  # Covers monthly min EOD balances up to ~1.67 Crore INR


@dataclass(frozen=True)
class MonthlyFinancialRecord:
    """Private borrower financial record for a single month (never shared with the verifier)."""

    month: int
    income: int
    debt: int
    min_eod_balance: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "month": self.month,
            "income": self.income,
            "debt": self.debt,
            "min_eod_balance": self.min_eod_balance,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MonthlyFinancialRecord":
        return cls(
            month=int(data["month"]),
            income=int(data["income"]),
            debt=int(data["debt"]),
            min_eod_balance=int(data["min_eod_balance"]),
        )


@dataclass(frozen=True)
class UnderwritingPolicy:
    """Public lender credit policy thresholds."""

    min_annual_net_cashflow: int = 480_000  # e.g. ₹4,80,000 / year net disposable cashflow
    max_dti_pct: int = 40  # e.g. Debt-to-Income <= 40%
    min_monthly_eod_balance: int = 5_000  # e.g. Min EOD >= ₹5,000 every month (no overdrafts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_annual_net_cashflow": self.min_annual_net_cashflow,
            "max_dti_pct": self.max_dti_pct,
            "min_monthly_eod_balance": self.min_monthly_eod_balance,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnderwritingPolicy":
        return cls(
            min_annual_net_cashflow=int(data.get("min_annual_net_cashflow", 480_000)),
            max_dti_pct=int(data.get("max_dti_pct", 40)),
            min_monthly_eod_balance=int(data.get("min_monthly_eod_balance", 5_000)),
        )


@dataclass(frozen=True)
class MonthlyCommitment:
    """Public Account-Aggregator attested Pedersen commitments for month m (zero raw values)."""

    month: int
    c_income: int
    c_debt: int
    c_balance: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "month": self.month,
            "c_income": hex(self.c_income),
            "c_debt": hex(self.c_debt),
            "c_balance": hex(self.c_balance),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MonthlyCommitment":
        return cls(
            month=int(data["month"]),
            c_income=int(str(data["c_income"]), 0),
            c_debt=int(str(data["c_debt"]), 0),
            c_balance=int(str(data["c_balance"]), 0),
        )


@dataclass(frozen=True)
class CreditProofBundle:
    """
    Complete zero-knowledge credit underwriting proof bundle sent to the lender/verifier.
    Contains ONLY public Pedersen commitments and non-interactive zero-knowledge range proofs.
    """

    applicant_id: str
    policy: UnderwritingPolicy
    monthly_commitments: List[MonthlyCommitment]
    c_annual_income: int
    c_annual_debt: int
    c_net_cashflow: int
    c_dti_margin: int
    net_cashflow_proof: RangeProof
    dti_proof: RangeProof
    eod_balance_proofs: List[RangeProof]
    generation_ms: float

    def total_proof_bytes(self) -> int:
        """Total compact binary size of all commitments and range proofs in bytes."""
        # 12 * 3 monthly commitments + 4 aggregate commitments = 40 * 32B = 1280B
        commitments_bytes = 40 * 32
        proofs_bytes = (
            self.net_cashflow_proof.byte_size()
            + self.dti_proof.byte_size()
            + sum(p.byte_size() for p in self.eod_balance_proofs)
        )
        return commitments_bytes + proofs_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "applicant_id": self.applicant_id,
            "policy": self.policy.to_dict(),
            "monthly_commitments": [mc.to_dict() for mc in self.monthly_commitments],
            "c_annual_income": hex(self.c_annual_income),
            "c_annual_debt": hex(self.c_annual_debt),
            "c_net_cashflow": hex(self.c_net_cashflow),
            "c_dti_margin": hex(self.c_dti_margin),
            "net_cashflow_proof": self.net_cashflow_proof.to_dict(),
            "dti_proof": self.dti_proof.to_dict(),
            "eod_balance_proofs": [p.to_dict() for p in self.eod_balance_proofs],
            "generation_ms": round(self.generation_ms, 3),
            "total_proof_bytes": self.total_proof_bytes(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CreditProofBundle":
        return cls(
            applicant_id=str(data["applicant_id"]),
            policy=UnderwritingPolicy.from_dict(data["policy"]),
            monthly_commitments=[
                MonthlyCommitment.from_dict(mc) for mc in data["monthly_commitments"]
            ],
            c_annual_income=int(str(data["c_annual_income"]), 0),
            c_annual_debt=int(str(data["c_annual_debt"]), 0),
            c_net_cashflow=int(str(data["c_net_cashflow"]), 0),
            c_dti_margin=int(str(data["c_dti_margin"]), 0),
            net_cashflow_proof=RangeProof.from_dict(data["net_cashflow_proof"]),
            dti_proof=RangeProof.from_dict(data["dti_proof"]),
            eod_balance_proofs=[
                RangeProof.from_dict(p) for p in data["eod_balance_proofs"]
            ],
            generation_ms=float(data.get("generation_ms", 0.0)),
        )


@dataclass(frozen=True)
class UnderwritingVerificationResult:
    """Detailed verification report produced by the zero-knowledge credit verifier."""

    applicant_id: str
    verified: bool
    homomorphic_consistency_ok: bool
    net_cashflow_ok: bool
    dti_ok: bool
    eod_balances_ok: bool
    failed_months: List[int]
    proof_size_bytes: int
    verification_ms: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "applicant_id": self.applicant_id,
            "verified": self.verified,
            "homomorphic_consistency_ok": self.homomorphic_consistency_ok,
            "net_cashflow_ok": self.net_cashflow_ok,
            "dti_ok": self.dti_ok,
            "eod_balances_ok": self.eod_balances_ok,
            "failed_months": self.failed_months,
            "proof_size_bytes": self.proof_size_bytes,
            "verification_ms": round(self.verification_ms, 3),
            "reason": self.reason,
        }


def generate_credit_proof(
    applicant_id: str,
    records: Sequence[MonthlyFinancialRecord],
    policy: UnderwritingPolicy = UnderwritingPolicy(),
    allow_forged: bool = False,
    group: PedersenGroup = DEFAULT_GROUP,
) -> CreditProofBundle:
    """
    Generates a zero-knowledge `CreditProofBundle` from 12 months of private financial records.

    If `allow_forged=False` (default), raises a `ValueError` if the borrower violates any
    policy threshold. If `allow_forged=True` (used for adversarial soundness tests and UI
    rejection demos), constructs forged range proofs for violated predicates so the verifier
    can cryptographically detect and reject them.
    """
    if len(records) != 12:
        raise ValueError(f"Expected 12 monthly records, got {len(records)}.")

    t0 = time.perf_counter()
    sorted_records = sorted(records, key=lambda r: r.month)

    monthly_commitments: List[MonthlyCommitment] = []
    r_incomes: List[int] = []
    r_debts: List[int] = []
    r_balances: List[int] = []

    for idx, rec in enumerate(sorted_records, start=1):
        if rec.month != idx:
            raise ValueError(f"Monthly records must be numbered 1..12, missing month {idx}.")
        c_inc, r_inc = group.commit(rec.income)
        c_deb, r_deb = group.commit(rec.debt)
        c_bal, r_bal = group.commit(rec.min_eod_balance)
        monthly_commitments.append(
            MonthlyCommitment(
                month=rec.month,
                c_income=c_inc,
                c_debt=c_deb,
                c_balance=c_bal,
            )
        )
        r_incomes.append(r_inc)
        r_debts.append(r_deb)
        r_balances.append(r_bal)

    total_income = sum(r.income for r in sorted_records)
    total_debt = sum(r.debt for r in sorted_records)
    net_cashflow = total_income - total_debt
    dti_margin = policy.max_dti_pct * total_income - 100 * total_debt

    r_total_income = sum(r_incomes) % group.q
    r_total_debt = sum(r_debts) % group.q
    r_net_cashflow = (r_total_income - r_total_debt) % group.q
    r_dti_margin = (policy.max_dti_pct * r_total_income - 100 * r_total_debt) % group.q

    # Compute homomorphic aggregate commitments from monthly commitments
    c_annual_income = 1
    c_annual_debt = 1
    for mc in monthly_commitments:
        c_annual_income = group.add_commitments(c_annual_income, mc.c_income)
        c_annual_debt = group.add_commitments(c_annual_debt, mc.c_debt)

    c_net_cashflow = group.sub_commitments(c_annual_income, c_annual_debt)
    c_dti_margin = group.sub_commitments(
        group.scale_commitment(c_annual_income, policy.max_dti_pct),
        group.scale_commitment(c_annual_debt, 100),
    )

    # 1. Prove Annual Net Disposable Cashflow >= policy.min_annual_net_cashflow
    net_ctx = f"{applicant_id}|net_cashflow|{policy.min_annual_net_cashflow}"
    if net_cashflow >= policy.min_annual_net_cashflow:
        net_proof = prove_range(
            value=net_cashflow,
            blinding=r_net_cashflow,
            commitment=c_net_cashflow,
            lower_bound=policy.min_annual_net_cashflow,
            bit_length=CASHFLOW_BIT_LENGTH,
            context=net_ctx,
            group=group,
        )
    elif allow_forged:
        net_proof = forge_range_proof_attempt(
            actual_value=net_cashflow,
            blinding=r_net_cashflow,
            lower_bound=policy.min_annual_net_cashflow,
            bit_length=CASHFLOW_BIT_LENGTH,
            context=net_ctx,
            group=group,
        )
    else:
        raise ValueError(
            f"Annual net cashflow {net_cashflow} is below policy minimum {policy.min_annual_net_cashflow}."
        )

    # 2. Prove DTI <= max_dti_pct% <=> max_dti_pct * sum(I_m) - 100 * sum(D_m) >= 0
    dti_ctx = f"{applicant_id}|dti_margin|{policy.max_dti_pct}"
    if dti_margin >= 0:
        dti_proof = prove_range(
            value=dti_margin,
            blinding=r_dti_margin,
            commitment=c_dti_margin,
            lower_bound=0,
            bit_length=DTI_MARGIN_BIT_LENGTH,
            context=dti_ctx,
            group=group,
        )
    elif allow_forged:
        dti_proof = forge_range_proof_attempt(
            actual_value=dti_margin,
            blinding=r_dti_margin,
            lower_bound=0,
            bit_length=DTI_MARGIN_BIT_LENGTH,
            context=dti_ctx,
            group=group,
        )
    else:
        actual_dti = (100.0 * total_debt / total_income) if total_income > 0 else 999.0
        raise ValueError(
            f"Debt-to-Income ratio {actual_dti:.2f}% exceeds policy cap {policy.max_dti_pct}%."
        )

    # 3. Prove Monthly Minimum EOD Balance >= policy.min_monthly_eod_balance for all 12 months
    eod_proofs: List[RangeProof] = []
    for rec, mc, r_bal in zip(sorted_records, monthly_commitments, r_balances):
        bal_ctx = f"{applicant_id}|eod_month_{rec.month}|{policy.min_monthly_eod_balance}"
        if rec.min_eod_balance >= policy.min_monthly_eod_balance:
            b_proof = prove_range(
                value=rec.min_eod_balance,
                blinding=r_bal,
                commitment=mc.c_balance,
                lower_bound=policy.min_monthly_eod_balance,
                bit_length=BALANCE_BIT_LENGTH,
                context=bal_ctx,
                group=group,
            )
        elif allow_forged:
            b_proof = forge_range_proof_attempt(
                actual_value=rec.min_eod_balance,
                blinding=r_bal,
                lower_bound=policy.min_monthly_eod_balance,
                bit_length=BALANCE_BIT_LENGTH,
                context=bal_ctx,
                group=group,
            )
        else:
            raise ValueError(
                f"Month {rec.month} min EOD balance {rec.min_eod_balance} is below {policy.min_monthly_eod_balance}."
            )
        eod_proofs.append(b_proof)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return CreditProofBundle(
        applicant_id=applicant_id,
        policy=policy,
        monthly_commitments=monthly_commitments,
        c_annual_income=c_annual_income,
        c_annual_debt=c_annual_debt,
        c_net_cashflow=c_net_cashflow,
        c_dti_margin=c_dti_margin,
        net_cashflow_proof=net_proof,
        dti_proof=dti_proof,
        eod_balance_proofs=eod_proofs,
        generation_ms=elapsed_ms,
    )


def verify_credit_proof(
    bundle: CreditProofBundle,
    expected_policy: UnderwritingPolicy | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> UnderwritingVerificationResult:
    """
    Verifies a `CreditProofBundle` using ONLY the public commitments and policy thresholds.
    Zero raw income, debt, or balance numbers are ever accessed.
    """
    t0 = time.perf_counter()
    policy = expected_policy if expected_policy is not None else bundle.policy

    # Check policy parameters match
    if (
        bundle.policy.min_annual_net_cashflow != policy.min_annual_net_cashflow
        or bundle.policy.max_dti_pct != policy.max_dti_pct
        or bundle.policy.min_monthly_eod_balance != policy.min_monthly_eod_balance
    ):
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return UnderwritingVerificationResult(
            applicant_id=bundle.applicant_id,
            verified=False,
            homomorphic_consistency_ok=False,
            net_cashflow_ok=False,
            dti_ok=False,
            eod_balances_ok=False,
            failed_months=[],
            proof_size_bytes=bundle.total_proof_bytes(),
            verification_ms=elapsed_ms,
            reason="Policy mismatch between proof bundle and verifier policy thresholds.",
        )

    if len(bundle.monthly_commitments) != 12 or len(bundle.eod_balance_proofs) != 12:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return UnderwritingVerificationResult(
            applicant_id=bundle.applicant_id,
            verified=False,
            homomorphic_consistency_ok=False,
            net_cashflow_ok=False,
            dti_ok=False,
            eod_balances_ok=False,
            failed_months=[],
            proof_size_bytes=bundle.total_proof_bytes(),
            verification_ms=elapsed_ms,
            reason="Bundle must contain exactly 12 monthly commitments and 12 EOD proofs.",
        )

    # 1. Recompute homomorphic aggregate commitments from the 12 monthly AA commitments
    recomputed_income = 1
    recomputed_debt = 1
    elements_valid = True
    for idx, mc in enumerate(bundle.monthly_commitments, start=1):
        if mc.month != idx:
            elements_valid = False
            break
        if not (
            group.is_valid_element(mc.c_income)
            and group.is_valid_element(mc.c_debt)
            and group.is_valid_element(mc.c_balance)
        ):
            elements_valid = False
            break
        recomputed_income = group.add_commitments(recomputed_income, mc.c_income)
        recomputed_debt = group.add_commitments(recomputed_debt, mc.c_debt)

    recomputed_net = group.sub_commitments(recomputed_income, recomputed_debt)
    recomputed_dti = group.sub_commitments(
        group.scale_commitment(recomputed_income, policy.max_dti_pct),
        group.scale_commitment(recomputed_debt, 100),
    )

    homomorphic_ok = (
        elements_valid
        and bundle.c_annual_income == recomputed_income
        and bundle.c_annual_debt == recomputed_debt
        and bundle.c_net_cashflow == recomputed_net
        and bundle.c_dti_margin == recomputed_dti
    )

    # 2. Verify Net Disposable Cashflow range proof against recomputed_net
    net_ctx = f"{bundle.applicant_id}|net_cashflow|{policy.min_annual_net_cashflow}"
    net_ok = homomorphic_ok and verify_range(
        proof=bundle.net_cashflow_proof,
        expected_commitment=recomputed_net,
        expected_lower_bound=policy.min_annual_net_cashflow,
        expected_bit_length=CASHFLOW_BIT_LENGTH,
        context=net_ctx,
        group=group,
    )

    # 3. Verify DTI ratio range proof against recomputed_dti
    dti_ctx = f"{bundle.applicant_id}|dti_margin|{policy.max_dti_pct}"
    dti_ok = homomorphic_ok and verify_range(
        proof=bundle.dti_proof,
        expected_commitment=recomputed_dti,
        expected_lower_bound=0,
        expected_bit_length=DTI_MARGIN_BIT_LENGTH,
        context=dti_ctx,
        group=group,
    )

    # 4. Verify all 12 monthly EOD balance range proofs
    failed_months: List[int] = []
    for mc, b_proof in zip(bundle.monthly_commitments, bundle.eod_balance_proofs):
        bal_ctx = f"{bundle.applicant_id}|eod_month_{mc.month}|{policy.min_monthly_eod_balance}"
        ok = verify_range(
            proof=b_proof,
            expected_commitment=mc.c_balance,
            expected_lower_bound=policy.min_monthly_eod_balance,
            expected_bit_length=BALANCE_BIT_LENGTH,
            context=bal_ctx,
            group=group,
        )
        if not ok:
            failed_months.append(mc.month)

    eod_ok = len(failed_months) == 0
    verified = homomorphic_ok and net_ok and dti_ok and eod_ok

    reasons: List[str] = []
    if not homomorphic_ok:
        reasons.append("Homomorphic aggregate commitment mismatch (forged opening/linear combination)")
    if not net_ok:
        reasons.append(f"Annual net cashflow proof failed (< ₹{policy.min_annual_net_cashflow:,})")
    if not dti_ok:
        reasons.append(f"DTI ratio proof failed (> {policy.max_dti_pct}% cap)")
    if not eod_ok:
        reasons.append(f"Monthly EOD balance floor failed in month(s): {failed_months}")

    reason_str = (
        "All zero-knowledge credit underwriting predicates verified."
        if verified
        else "; ".join(reasons)
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return UnderwritingVerificationResult(
        applicant_id=bundle.applicant_id,
        verified=verified,
        homomorphic_consistency_ok=homomorphic_ok,
        net_cashflow_ok=net_ok,
        dti_ok=dti_ok,
        eod_balances_ok=eod_ok,
        failed_months=failed_months,
        proof_size_bytes=bundle.total_proof_bytes(),
        verification_ms=elapsed_ms,
        reason=reason_str,
    )
