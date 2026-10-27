"""
FastAPI Service for Zero-Knowledge Credit Underwriting & Neo-Bank Proof of Solvency.

Endpoints:
- GET  /                  -> Interactive dark/light web console (web/console.html)
- GET  /healthz, /readyz  -> Liveness and readiness; GET /metrics -> Prometheus [metrics]
- GET  /params            -> Group parameters and the FIP public key in use
- GET  /presets           -> Preset borrower & neo-bank solvency configurations
- POST /underwrite/prove  -> Generate a CreditProofBundle, simulating the FIP (development only) [prove]
- POST /underwrite/verify -> Verify a CreditProofBundle against the pinned FIP key; recorded [verify]
- GET  /underwrite/verifications[/{id}] -> Recorded verifications [read]
- POST /solvency/audit    -> Build & audit a Merkle-Sum Proof-of-Solvency; published [solvency]
- GET  /solvency/audits[/{id}] -> Published proofs of solvency and their roots [read]
- GET  /bench             -> Run completeness, soundness, proof-size & latency benchmark [bench]

The zero-knowledge protocols here are hand-written and have NOT been reviewed by a
cryptographer. Production mode refuses to start unless ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes,
and needs ZKCREDIT_FIP_PUBLIC_KEY (the FIP's Ed25519 key, 64 hex). Callers send an API key whose
role decides the permissions in brackets; see ops.py and docs/runbook.md.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import db, ops
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
from .store import ProofStore

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
UNREVIEWED = ("zkcredit's range proofs, OR-proofs and Merkle-sum solvency proofs are hand-written and have not "
              "been reviewed by a cryptographer")
if settings.production and os.environ.get("ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO", "").strip().lower() != "yes":
    raise ops.ConfigError(UNREVIEWED + "; set ZKCREDIT_ACCEPT_UNREVIEWED_CRYPTO=yes to run anyway")
ops.log.warning(UNREVIEWED)

_FIP_HEX = os.environ.get("ZKCREDIT_FIP_PUBLIC_KEY", "").strip().lower()
if settings.production and not _FIP_HEX:
    raise ops.ConfigError("production needs ZKCREDIT_FIP_PUBLIC_KEY: the FIP's Ed25519 public key (64 hex)")
if _FIP_HEX:
    if not re.fullmatch(r"[0-9a-f]{64}", _FIP_HEX):
        raise ops.ConfigError("ZKCREDIT_FIP_PUBLIC_KEY must be 64 hex characters")
    FIP_KEY = None  # the FIP signs; the lender only verifies
    FIP_PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_FIP_HEX))
else:
    # Demo FIP signing key, new on every start (development only).
    FIP_KEY = Ed25519PrivateKey.generate()
    FIP_PUBLIC_KEY = FIP_KEY.public_key()

store = ProofStore(db.connect(settings.database_url))

app = FastAPI(
    title="ZKCredit: Zero-Knowledge Credit Underwriting & Proof-of-Solvency Engine",
    version="1.0.0",
    description=(
        "Pedersen Commitments, CDS 1-of-2 OR-Sigma Bit-Decomposition Range Proofs, "
        "Account Aggregator ZK Credit Underwriting, and Merkle-Sum Proof of Solvency."
    ),
)

ops.install(app, settings, {"database": lambda: store.db.connect().close()})

_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
MAX_ACCOUNTS = 64  # each leaf costs a range proof; this keeps one request to a few seconds
MAX_AMOUNT = 10**12  # rupees; anything larger is a typo or an attempt to burn CPU



def _no_demo_in_production(allow_forged: bool) -> None:
    if allow_forged and settings.production:
        raise HTTPException(403, "forged-proof demos are disabled in production")


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


@app.get("/params", dependencies=[Depends(ops.require("read"))])
def params() -> Dict[str, Any]:
    return {
        "crypto_review": "none: " + UNREVIEWED,
        "group": {
            "name": DEFAULT_GROUP.name,
            "subgroup_bits": DEFAULT_GROUP.q.bit_length(),
            "q": hex(DEFAULT_GROUP.q),
            "g": DEFAULT_GROUP.g.hex(),
            "h": DEFAULT_GROUP.h.hex(),
        },
        "fip_public_key": FIP_PUBLIC_KEY.public_bytes_raw().hex(),
        "fip_key_source": "pinned (ZKCREDIT_FIP_PUBLIC_KEY)" if FIP_KEY is None else "demo key made at start-up",
    }


@app.get("/presets", dependencies=[Depends(ops.require("read"))])
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


@app.post("/underwrite/prove", dependencies=[Depends(ops.require("prove"))])
def underwrite_prove(req: UnderwriteProveRequest) -> Dict[str, Any]:
    if FIP_KEY is None:
        raise HTTPException(403, "proving simulates the FIP's signature; it is not available with a pinned FIP key")
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


@app.post("/underwrite/verify")
def underwrite_verify(req: UnderwriteVerifyRequest, ident: dict = Depends(ops.require("verify"))) -> Dict[str, Any]:
    try:
        bundle = CreditProofBundle.from_dict(req.bundle)
    except Exception:  # any malformed field: say so without echoing it
        raise HTTPException(status_code=400, detail="invalid CreditProofBundle") from None

    expected_policy = None
    if req.expected_policy is not None:
        expected_policy = UnderwritingPolicy(
            min_annual_net_cashflow=req.expected_policy.min_annual_net_cashflow,
            max_dti_pct=req.expected_policy.max_dti_pct,
            min_monthly_eod_balance=req.expected_policy.min_monthly_eod_balance,
        )

    result = verify_credit_proof(bundle, expected_policy=expected_policy, fip_public_key=FIP_PUBLIC_KEY).to_dict()
    ops.DECISIONS.labels(decision="credit_verified" if result["verified"] else "credit_rejected").inc()
    result["verification_id"] = store.record_verification(ident["user"] or "demo", result, bundle.to_dict())
    return result


@app.post("/solvency/audit")
def solvency_audit(req: SolvencyAuditRequest, ident: dict = Depends(ops.require("solvency"))) -> Dict[str, Any]:
    _no_demo_in_production(req.allow_forged)
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

    audit = verify_solvency_audit(bundle).to_dict()
    ops.DECISIONS.labels(decision="solvency_verified" if audit["verified"] else "solvency_rejected").inc()
    public = bundle.to_dict()
    return {
        "audit_id": store.record_audit(ident["user"] or "demo", audit, public),
        "bundle": public,
        "audit": audit,
        # Private to the sampled customer (balance, blinding, nonce); the demo returns it
        # here so the console can show what that customer would check.
        "customer_inclusion_proof": bundle.sample_inclusion_proof.to_dict(),
    }


@app.get("/underwrite/verifications", dependencies=[Depends(ops.require("read"))])
def list_verifications(applicant_id: Optional[str] = Query(None, max_length=64),
                       limit: int = Query(50, ge=1, le=1000)) -> Dict[str, Any]:
    return {"verifications": store.summaries("credit_verifications", applicant_id, limit)}


@app.get("/underwrite/verifications/{ref}", dependencies=[Depends(ops.require("read"))])
def get_verification(ref: str) -> Dict[str, Any]:
    row = store.get("credit_verifications", ref[:64])
    if row is None:
        raise HTTPException(404, "verification not found")
    return row


@app.get("/solvency/audits", dependencies=[Depends(ops.require("read"))])
def list_audits(bank_id: Optional[str] = Query(None, max_length=64), limit: int = Query(50, ge=1, le=1000)) -> Dict[str, Any]:
    return {"audits": store.summaries("solvency_audits", bank_id, limit)}


@app.get("/solvency/audits/{ref}", dependencies=[Depends(ops.require("read"))])
def get_audit(ref: str) -> Dict[str, Any]:
    row = store.get("solvency_audits", ref[:64])
    if row is None:
        raise HTTPException(404, "audit not found")
    return row


@app.get("/bench", dependencies=[Depends(ops.require("bench"))])
def bench() -> Dict[str, Any]:
    return run_benchmark()
