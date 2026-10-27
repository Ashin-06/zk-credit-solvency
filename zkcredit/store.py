"""Credit-proof verifications and published proofs of solvency, kept in the database (see db.py).
Only public material is stored: commitments, proofs and verification reports."""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Engine

_SUMMARY = {  # table -> (summary columns, filter column); fixed strings, never caller input
    "credit_verifications": ("id, created_at, requested_by, applicant_id, verified", "applicant_id"),
    "solvency_audits": ("id, created_at, requested_by, bank_id, root_hash, verified", "bank_id"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _decode(row) -> dict:
    d = dict(row)
    d["verified"] = bool(d["verified"])
    for f in ("result", "bundle", "audit"):
        if f in d:
            d[f] = json.loads(d[f])
    return d


class ProofStore:
    def __init__(self, engine: Engine):
        self.db = engine
        self._lock = threading.Lock()

    def record_verification(self, user: str, result: dict, bundle: dict) -> str:
        ref = uuid.uuid4().hex
        with self._lock, self.db.begin() as c:
            c.execute(text("INSERT INTO credit_verifications VALUES (:i, :t, :u, :a, :v, :r, :b)"),
                      {"i": ref, "t": _now(), "u": user, "a": result["applicant_id"], "v": int(bool(result["verified"])),
                       "r": json.dumps(result), "b": json.dumps(bundle)})
        return ref

    def record_audit(self, user: str, audit: dict, bundle: dict) -> str:
        ref = uuid.uuid4().hex
        with self._lock, self.db.begin() as c:
            c.execute(text("INSERT INTO solvency_audits VALUES (:i, :t, :u, :b, :h, :v, :a, :bd)"),
                      {"i": ref, "t": _now(), "u": user, "b": bundle["bank_id"], "h": bundle["root_hash"],
                       "v": int(bool(audit["verified"])), "a": json.dumps(audit), "bd": json.dumps(bundle)})
        return ref

    def summaries(self, table: str, value: str | None = None, limit: int = 50) -> list[dict]:
        cols, key = _SUMMARY[table]
        where = f" WHERE {key} = :k" if value else ""
        sql = f"SELECT {cols} FROM {table}{where} ORDER BY created_at DESC LIMIT :n"  # nosec B608 - names come from _SUMMARY, not the caller
        with self.db.connect() as c:
            return [_decode(r) for r in c.execute(text(sql), {"k": value, "n": limit}).mappings()]

    def get(self, table: str, ref: str) -> dict | None:
        if table not in _SUMMARY:
            raise KeyError(table)
        with self.db.connect() as c:
            r = c.execute(text(f"SELECT * FROM {table} WHERE id = :i"), {"i": ref}).mappings().first()  # nosec B608
        return None if r is None else _decode(r)
