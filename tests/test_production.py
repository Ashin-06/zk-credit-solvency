"""Settings, the unreviewed-crypto and FIP-key rules, auth, limits, headers, metrics, health,
stored verifications and proofs of solvency, and migrations."""
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import text

from zkcredit import db, ops

KEY = "zkcredit_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "lender-1", "role": "lender"}}
FIP_PUB = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
SMALL_BANK = {"bank_id": "TINY-BANK", "liquid_reserves": 1000,
              "accounts": [{"user_id": "u1", "balance": 100}, {"user_id": "u2", "balance": 250}]}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("ZKCREDIT_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"ZKCREDIT_{k}", v)
    import zkcredit.api as api

    return importlib.reload(api)


PROD = {"ENV": "production", "API_KEYS": json.dumps(HASHED), "DATABASE_URL": "sqlite://"}


def test_production_refuses_unreviewed_crypto_without_consent(monkeypatch):
    with pytest.raises(ops.ConfigError, match="not been reviewed by a cryptographer"):
        boot(monkeypatch, **PROD, FIP_PUBLIC_KEY=FIP_PUB)
    with pytest.raises(ops.ConfigError, match="FIP_PUBLIC_KEY"):
        boot(monkeypatch, **PROD, ACCEPT_UNREVIEWED_CRYPTO="yes")
    with pytest.raises(ops.ConfigError, match="64 hex"):
        boot(monkeypatch, **PROD, ACCEPT_UNREVIEWED_CRYPTO="yes", FIP_PUBLIC_KEY="abc")
    api = boot(monkeypatch, **PROD, ACCEPT_UNREVIEWED_CRYPTO="yes", FIP_PUBLIC_KEY=FIP_PUB)
    assert api.FIP_KEY is None and api.FIP_PUBLIC_KEY.public_bytes_raw().hex() == FIP_PUB
    admin = {f"sha256:{hashlib.sha256(b'admin-key-' + b'y' * 30).hexdigest()}": {"user": "ops", "role": "admin"}}
    api = boot(monkeypatch, **{**PROD, "API_KEYS": json.dumps(admin)}, ACCEPT_UNREVIEWED_CRYPTO="yes", FIP_PUBLIC_KEY=FIP_PUB)
    c = TestClient(api.app)
    h = {"x-api-key": "admin-key-" + "y" * 30}
    assert c.post("/underwrite/prove", json={"preset_key": "prime_salaried"}, headers=h).status_code == 403
    assert c.post("/solvency/audit", json={**SMALL_BANK, "allow_forged": True}, headers=h).status_code == 403
    params = c.get("/params", headers=h).json()
    assert params["crypto_review"].startswith("none") and params["fip_key_source"].startswith("pinned")


@pytest.mark.parametrize("change, message", [
    ({"ZKCREDIT_API_KEYS": None}, "API keys"),
    ({"ZKCREDIT_DATABASE_URL": None}, "DATABASE_URL"),
    ({"ZKCREDIT_API_KEYS": json.dumps({KEY: {"user": "p", "role": "lender"}})}, "sha256"),
    ({"ZKCREDIT_CORS_ORIGINS": "*"}, "CORS"),
])
def test_production_settings_refused(change, message):
    env = {"ZKCREDIT_ENV": "production", "ZKCREDIT_API_KEYS": json.dumps(HASHED), "ZKCREDIT_DATABASE_URL": "sqlite://"}
    env.update(change)
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings({k: v for k, v in env.items() if v is not None})


def test_no_public_bind_and_readable_exit():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"ZKCREDIT_HOST": "0.0.0.0"})
    env = {k: v for k, v in os.environ.items() if not k.startswith("ZKCREDIT_")}
    r = subprocess.run([sys.executable, "-m", "zkcredit", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    keys = {"k-app": {"user": "borrower", "role": "applicant"}, "k-lend": {"user": "lender-1", "role": "lender"},
            "k-bank": {"user": "neobank", "role": "bank"}, "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    bundle = c.post("/underwrite/prove", json={"preset_key": "prime_salaried"}, headers={"x-api-key": "k-app"}).json()["bundle"]
    assert c.post("/underwrite/verify", json={"bundle": bundle}).status_code == 401
    assert c.post("/underwrite/verify", json={"bundle": bundle}, headers={"x-api-key": "k-app"}).status_code == 403
    assert c.post("/underwrite/verify", json={"bundle": bundle}, headers={"x-api-key": "k-lend"}).status_code == 200
    assert c.post("/solvency/audit", json=SMALL_BANK, headers={"x-api-key": "k-lend"}).status_code == 403
    assert c.post("/solvency/audit", json=SMALL_BANK, headers={"x-api-key": "k-bank"}).status_code == 200
    assert c.get("/bench", headers={"x-api-key": "k-bank"}).status_code == 403  # admin only: slow
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'zkcredit_decisions_total{decision="credit_verified"} ' in m.text


def test_verifications_and_audits_survive_a_restart(monkeypatch, tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'zk.db'}"
    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)
    bundle = c.post("/underwrite/prove", json={"preset_key": "prime_salaried"}).json()["bundle"]
    v = c.post("/underwrite/verify", json={"bundle": bundle}).json()
    audit = c.post("/solvency/audit", json=SMALL_BANK).json()
    assert v["verified"] is True and audit["audit"]["verified"] is True

    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)  # restart
    got = c.get(f"/underwrite/verifications/{v['verification_id']}").json()
    assert got["verified"] is True and got["applicant_id"] == bundle["applicant_id"] and got["bundle"] == bundle
    published = c.get(f"/solvency/audits/{audit['audit_id']}").json()
    assert published["root_hash"] == audit["bundle"]["root_hash"] and published["bank_id"] == "TINY-BANK"
    assert "sample_inclusion_proof" not in json.dumps(published)  # the sampled customer's secrets aren't kept
    assert any(a["id"] == audit["audit_id"] for a in c.get("/solvency/audits", params={"bank_id": "TINY-BANK"}).json()["audits"])
    # the old demo FIP key is gone after the restart, so the same bundle no longer verifies
    assert c.post("/underwrite/verify", json={"bundle": bundle}).json()["verified"] is False
    assert c.get("/underwrite/verifications/nope").status_code == 404


def test_limits_headers_errors_and_health(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/presets").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    api = boot(monkeypatch, MAX_BODY_BYTES="500")

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: balance 123456")

    c = TestClient(api.app)
    assert c.post("/underwrite/verify", json={"bundle": {"x": "y" * 600}}).status_code == 413

    def chunks():
        for _ in range(10):
            yield b"a" * 100

    assert c.post("/solvency/audit", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    crash = c.get("/boom")
    assert crash.status_code == 500 and "123456" not in crash.text and crash.json()["request_id"]
    bad = c.post("/underwrite/verify", json={"bundle": {"applicant_id": "SECRET-APPLICANT"}})
    assert bad.status_code == 400 and "SECRET" not in bad.text
    r = c.get("/presets", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123" and r.headers["content-security-policy"] == ops.API_CSP
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json()["checks"] == {"database": True}


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"] and db.migrate(eng) == []
    with eng.connect() as c:
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"credit_verifications", "solvency_audits", "schema_migrations"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("ZKCREDIT_")}, "ZKCREDIT_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "zkcredit", "migrate"], env=env, capture_output=True, text=True,
                         timeout=120, check=False)
    assert out.returncode == 0 and "up to date" in out.stdout
