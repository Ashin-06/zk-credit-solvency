"""
FastAPI Service for Zero-Knowledge Credit Underwriting & Neo-Bank Proof of Solvency.

Endpoints:
- GET  /                  -> Interactive dark/light web console (web/console.html)
- GET  /health            -> Service health & group parameters
- GET  /presets           -> Preset borrower & neo-bank solvency configurations
- POST /underwrite/prove  -> Generate a zero-knowledge CreditProofBundle from 12-month records
- POST /underwrite/verify -> Verify a CreditProofBundle using only public commitments & thresholds
- POST /solvency/audit    -> Build & audit a Merkle-Sum Commitment Tree Proof-of-Solvency
- GET  /bench             -> Run completeness, soundness, proof-size & latency benchmark

Set ZKCREDIT_API_KEY to require it in the X-API-Key header on the POST endpoints and /bench
(unset = open, for local use; `python -m zkcredit serve` refuses a non-loopback host without it).
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .bench import get_borrower_presets, get_solvency_presets, run_benchmark
from .crypto import DEFAULT_GROUP
from .solvency import (
    CustomerAccount,
    build_solvency_proof,
    verify_solvency_audit,
)
from .underwrite import (
    CreditProofBundle,
    MonthlyFinancialRecord,
    UnderwritingPolicy,
    generate_credit_proof,
    verify_credit_proof,
)

app = FastAPI(
    title="ZKCredit: Zero-Knowledge Credit Underwriting & Proof-of-Solvency Engine",
    version="1.0.0",
    description=(
        "Pedersen Commitments, CDS 1-of-2 OR-Sigma Bit-Decomposition Range Proofs, "
        "Account Aggregator ZK Credit Underwriting, and Merkle-Sum Proof of Solvency."
    ),
)

_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
API_KEY = os.environ.get("ZKCREDIT_API_KEY")
MAX_BODY_BYTES = 1_000_000  # a full credit bundle is about 200 KB of JSON
MAX_ACCOUNTS = 64  # each leaf costs a range proof; this keeps one request to a few seconds
MAX_AMOUNT = 10**12  # rupees; anything larger is a typo or an attempt to burn CPU


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and not hmac.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(401, "missing or wrong X-API-Key")


@app.middleware("http")
async def limit_body(request: Request, call_next):
    if request.method == "POST":
        length = request.headers.get("content-length", "")
        if not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "body missing Content-Length or over 1 MB"}, status_code=413)
    return await call_next(request)

# Demo FIP signing key, new on every start. A real lender pins the FIPs' published keys.
FIP_KEY = Ed25519PrivateKey.generate()
FIP_PUBLIC_KEY = FIP_KEY.public_key()


class MonthlyRecordInput(BaseModel):
    month: int = Field(..., ge=1, le=12)
    income: int = Field(..., ge=0, le=MAX_AMOUNT)
    debt: int = Field(..., ge=0, le=MAX_AMOUNT)
    min_eod_balance: int = Field(..., ge=-MAX_AMOUNT, le=MAX_AMOUNT)


class PolicyInput(BaseModel):
    min_annual_net_cashflow: int = Field(480_000, ge=-MAX_AMOUNT, le=MAX_AMOUNT)
    max_dti_pct: int = Field(40, ge=0, le=100)
    min_monthly_eod_balance: int = Field(5_000, ge=-MAX_AMOUNT, le=MAX_AMOUNT)


class UnderwriteProveRequest(BaseModel):
    applicant_id: str = Field("AA-IN-BORROWER-001", min_length=1, max_length=64)
    preset_key: Optional[str] = Field(None, max_length=64)
    policy: PolicyInput = Field(default_factory=PolicyInput)
    records: Optional[List[MonthlyRecordInput]] = Field(None, max_length=12)
    allow_forged: bool = False  # True builds forged proofs for failing predicates (rejection demo)


class UnderwriteVerifyRequest(BaseModel):
    bundle: Dict[str, Any]
    expected_policy: Optional[PolicyInput] = None


class CustomerAccountInput(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    balance: int = Field(..., ge=-MAX_AMOUNT, le=MAX_AMOUNT)


class SolvencyAuditRequest(BaseModel):
    bank_id: str = Field("NEOBANK-RESERVE-01", min_length=1, max_length=64)
    preset_key: Optional[str] = Field(None, max_length=64)
    liquid_reserves: int = Field(3_000_000, ge=0, le=MAX_AMOUNT)
    accounts: Optional[List[CustomerAccountInput]] = Field(None, max_length=MAX_ACCOUNTS)
    sample_user_index: int = Field(0, ge=0, lt=MAX_ACCOUNTS)
    allow_forged: bool = False  # True builds forged proofs for negative leaves (rejection demo)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    if _CONSOLE_PATH.exists():
        return HTMLResponse(_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>ZKCredit Console not found</h1>", status_code=404)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "zkcredit",
        "port": 8012,
        "group": {
            "name": DEFAULT_GROUP.name,
            "subgroup_bits": DEFAULT_GROUP.q.bit_length(),
            "q": hex(DEFAULT_GROUP.q),
            "g": DEFAULT_GROUP.g.hex(),
            "h": DEFAULT_GROUP.h.hex(),
        },
        "demo_fip_public_key": FIP_PUBLIC_KEY.public_bytes_raw().hex(),
    }


@app.get("/presets")
def presets() -> Dict[str, Any]:
    b_presets = get_borrower_presets()
    s_presets = get_solvency_presets()
    return {
        "borrowers": {
            k: {
                "applicant_id": v["applicant_id"],
                "label": v["label"],
                "description": v["description"],
                "expected_eligible": v["expected_eligible"],
                "records": [r.to_dict() for r in v["records"]],
            }
            for k, v in b_presets.items()
        },
        "solvency": {
            k: {
                "bank_id": v["bank_id"],
                "label": v["label"],
                "liquid_reserves": v["liquid_reserves"],
                "expected_solvent": v["expected_solvent"],
                "accounts": [a.to_dict() for a in v["accounts"]],
            }
            for k, v in s_presets.items()
        },
    }


@app.post("/underwrite/prove", dependencies=[Depends(require_key)])
def underwrite_prove(req: UnderwriteProveRequest) -> Dict[str, Any]:
    b_presets = get_borrower_presets()
    if req.preset_key and req.preset_key in b_presets:
        preset = b_presets[req.preset_key]
        applicant_id = preset["applicant_id"]
        records = preset["records"]
    elif req.records:
        applicant_id = req.applicant_id
        records = [
            MonthlyFinancialRecord(
                month=r.month,
                income=r.income,
                debt=r.debt,
                min_eod_balance=r.min_eod_balance,
            )
            for r in req.records
        ]
    else:
        preset = b_presets["prime_salaried"]
        applicant_id = preset["applicant_id"]
        records = preset["records"]

    policy = UnderwritingPolicy(
        min_annual_net_cashflow=req.policy.min_annual_net_cashflow,
        max_dti_pct=req.policy.max_dti_pct,
        min_monthly_eod_balance=req.policy.min_monthly_eod_balance,
    )

    try:
        bundle = generate_credit_proof(
            applicant_id=applicant_id,
            records=records,
            policy=policy,
            allow_forged=req.allow_forged,
            fip_key=FIP_KEY,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    verification = verify_credit_proof(bundle, expected_policy=policy, fip_public_key=FIP_PUBLIC_KEY)
    return {
        "bundle": bundle.to_dict(),
        "verification": verification.to_dict(),
    }


@app.post("/underwrite/verify", dependencies=[Depends(require_key)])
def underwrite_verify(req: UnderwriteVerifyRequest) -> Dict[str, Any]:
    try:
        bundle = CreditProofBundle.from_dict(req.bundle)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CreditProofBundle: {exc}") from exc

    expected_policy = None
    if req.expected_policy is not None:
        expected_policy = UnderwritingPolicy(
            min_annual_net_cashflow=req.expected_policy.min_annual_net_cashflow,
            max_dti_pct=req.expected_policy.max_dti_pct,
            min_monthly_eod_balance=req.expected_policy.min_monthly_eod_balance,
        )

    result = verify_credit_proof(bundle, expected_policy=expected_policy, fip_public_key=FIP_PUBLIC_KEY)
    return result.to_dict()


@app.post("/solvency/audit", dependencies=[Depends(require_key)])
def solvency_audit(req: SolvencyAuditRequest) -> Dict[str, Any]:
    s_presets = get_solvency_presets()
    if req.preset_key and req.preset_key in s_presets:
        preset = s_presets[req.preset_key]
        bank_id = preset["bank_id"]
        liquid_reserves = preset["liquid_reserves"]
        accounts = preset["accounts"]
    elif req.accounts:
        bank_id = req.bank_id
        liquid_reserves = req.liquid_reserves
        accounts = [CustomerAccount(user_id=a.user_id, balance=a.balance) for a in req.accounts]
    else:
        preset = s_presets["solvent_neobank"]
        bank_id = preset["bank_id"]
        liquid_reserves = preset["liquid_reserves"]
        accounts = preset["accounts"]

    try:
        bundle = build_solvency_proof(
            bank_id=bank_id,
            accounts=accounts,
            liquid_reserves=liquid_reserves,
            sample_user_index=req.sample_user_index,
            allow_forged=req.allow_forged,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit = verify_solvency_audit(bundle)
    return {
        "bundle": bundle.to_dict(),
        "audit": audit.to_dict(),
        # Private to the sampled customer (balance, blinding, nonce); the demo returns it
        # here so the console can show what that customer would check.
        "customer_inclusion_proof": bundle.sample_inclusion_proof.to_dict(),
    }


@app.get("/bench", dependencies=[Depends(require_key)])
def bench() -> Dict[str, Any]:
    return run_benchmark()
