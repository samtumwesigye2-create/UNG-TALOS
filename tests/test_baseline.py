import os
import time

os.environ.setdefault("TALOS_DB_PATH", "test_talos.db")
os.environ.setdefault("TALOS_ADMIN_EMAIL", "test-admin@ung-talos.local")
os.environ.setdefault("TALOS_ADMIN_PASSWORD", "TestPass123!")
os.environ.setdefault("TALOS_JWT_SECRET", "test-only-secret")
os.environ.setdefault("TALOS_POLL_INTERVAL_SECONDS", "0")

from fastapi.testclient import TestClient

from main import app
from db import get_db, init_db
from auth import bootstrap_admin_if_empty, new_totp_secret, totp_code
import integrity

client = TestClient(app)


def setup_module():
    if os.path.exists("test_talos.db"):
        os.remove("test_talos.db")
    init_db()
    bootstrap_admin_if_empty()


def test_health_identifies_talos():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "UNG-TALOS", "phase": 1}


def test_security_admin_login_requires_mfa():
    response = client.post("/auth/login", json={
        "email": "test-admin@ung-talos.local",
        "password": "TestPass123!",
    })
    assert response.status_code == 403


def test_integrity_chain_detects_tampering():
    conn = get_db()
    try:
        fields = {
            "rule": "test_rule",
            "severity": "warning",
            "source_system": "TEST",
            "summary": "original",
            "suggested_action": "review",
            "classification": "internal",
            "detected_at": time.time(),
        }
        prev_hash = integrity.get_last_hash(conn)
        record_hash = integrity.compute_hash(prev_hash, fields)
        conn.execute(
            "INSERT INTO incidents (rule, severity, source_system, summary, suggested_action, classification, status, detected_at, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
            (fields["rule"], fields["severity"], fields["source_system"], fields["summary"], fields["suggested_action"], fields["classification"], fields["detected_at"], prev_hash, record_hash),
        )
        conn.commit()
        assert integrity.verify_chain(conn)["ok"] is True
        conn.execute("UPDATE incidents SET summary='tampered' WHERE rule='test_rule'")
        conn.commit()
        result = integrity.verify_chain(conn)
        assert result["ok"] is False
    finally:
        conn.close()
