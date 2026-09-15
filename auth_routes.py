"""
UNG-TALOS — auth & user-management HTTP routes.
Same shape as UNG-OLYMPUS's auth_routes.py (rate-limited login, TOTP MFA
+ backup codes), simplified since there's no domain scoping here.
"""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import (
    CurrentUser, get_current_user, require_role,
    hash_password, verify_password, issue_token,
    new_totp_secret, verify_totp,
    generate_backup_codes, store_backup_codes, consume_backup_code,
    MFA_REQUIRED_ROLES,
)
from db import get_db, ROLES

router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])

RATE_LIMIT_THRESHOLD = 5
RATE_LIMIT_WINDOW = 15 * 60
RATE_LIMIT_LOCKOUT = 15 * 60


def _check_rate_limit(conn, email: str):
    row = conn.execute("SELECT * FROM login_attempts WHERE email=?", (email,)).fetchone()
    if row and row["locked_until"] and row["locked_until"] > time.time():
        retry_in = int(row["locked_until"] - time.time())
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {retry_in}s.")


def _record_failed_login(conn, email: str):
    now = time.time()
    row = conn.execute("SELECT * FROM login_attempts WHERE email=?", (email,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO login_attempts (email, failed_count, first_failed_at, locked_until) VALUES (?, 1, ?, NULL)",
            (email, now),
        )
    else:
        window_expired = row["first_failed_at"] is None or (now - row["first_failed_at"]) > RATE_LIMIT_WINDOW
        new_count = 1 if window_expired else row["failed_count"] + 1
        first_failed_at = now if window_expired else row["first_failed_at"]
        locked_until = now + RATE_LIMIT_LOCKOUT if new_count >= RATE_LIMIT_THRESHOLD else None
        conn.execute(
            "UPDATE login_attempts SET failed_count=?, first_failed_at=?, locked_until=? WHERE email=?",
            (new_count, first_failed_at, locked_until, email),
        )
    conn.commit()


def _clear_rate_limit(conn, email: str):
    conn.execute("DELETE FROM login_attempts WHERE email=?", (email,))
    conn.commit()


class LoginIn(BaseModel):
    email: str
    password: str
    totp_code: str | None = None
    backup_code: str | None = None


@router.post("/login")
def login(body: LoginIn):
    conn = get_db()
    try:
        _check_rate_limit(conn, body.email)
        row = conn.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()
        if row is None or not verify_password(body.password, row["password_hash"], row["salt"]):
            _record_failed_login(conn, body.email)
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if row["role"] in MFA_REQUIRED_ROLES:
            if not row["mfa_enabled"]:
                raise HTTPException(status_code=403, detail="MFA setup required for this role before login — call /auth/mfa/setup first")
            mfa_ok = bool(body.totp_code and verify_totp(row["mfa_secret"], body.totp_code))
            if not mfa_ok and body.backup_code:
                mfa_ok = consume_backup_code(conn, row["id"], body.backup_code)
            if not mfa_ok:
                _record_failed_login(conn, body.email)
                raise HTTPException(status_code=401, detail="Valid MFA code or backup code required")

        _clear_rate_limit(conn, body.email)
        token = issue_token(row)
        return {"access_token": token, "token_type": "bearer", "role": row["role"]}
    finally:
        conn.close()


@router.post("/mfa/setup")
def mfa_setup(user: CurrentUser = Depends(get_current_user)):
    secret = new_totp_secret()
    conn = get_db()
    try:
        conn.execute("UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?", (secret, user.uid))
        conn.commit()
    finally:
        conn.close()
    uri = f"otpauth://totp/UNG-TALOS:{user.email}?secret={secret}&issuer=UNG-TALOS"
    return {"secret": secret, "otpauth_uri": uri}


class MfaEnableIn(BaseModel):
    totp_code: str


@router.post("/mfa/enable")
def mfa_enable(body: MfaEnableIn, user: CurrentUser = Depends(get_current_user)):
    conn = get_db()
    try:
        row = conn.execute("SELECT mfa_secret FROM users WHERE id=?", (user.uid,)).fetchone()
        if row is None or not row["mfa_secret"]:
            raise HTTPException(status_code=400, detail="Call /auth/mfa/setup first")
        if not verify_totp(row["mfa_secret"], body.totp_code):
            raise HTTPException(status_code=401, detail="Invalid code")
        conn.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (user.uid,))
        conn.commit()
        codes = generate_backup_codes()
        store_backup_codes(conn, user.uid, codes)
        return {"mfa_enabled": True, "backup_codes": codes}
    finally:
        conn.close()


@router.post("/mfa/backup-codes/regenerate")
def regenerate_backup_codes(user: CurrentUser = Depends(get_current_user)):
    conn = get_db()
    try:
        row = conn.execute("SELECT mfa_enabled FROM users WHERE id=?", (user.uid,)).fetchone()
        if not row or not row["mfa_enabled"]:
            raise HTTPException(status_code=400, detail="MFA must be enabled first")
        codes = generate_backup_codes()
        store_backup_codes(conn, user.uid, codes)
        return {"backup_codes": codes}
    finally:
        conn.close()


class CreateUserIn(BaseModel):
    email: str
    password: str
    role: str


@users_router.post("")
def create_user(body: CreateUserIn, admin: CurrentUser = Depends(require_role("security_admin"))):
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {ROLES}")
    pw_hash, salt = hash_password(body.password)
    conn = get_db()
    try:
        try:
            cur = conn.execute(
                "INSERT INTO users (email, password_hash, salt, role, mfa_enabled, created_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (body.email, pw_hash, salt, body.role, time.time()),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="A user with that email already exists")
        conn.commit()
        return {"id": cur.lastrowid, "email": body.email, "role": body.role}
    finally:
        conn.close()


@users_router.get("")
def list_users(admin: CurrentUser = Depends(require_role("security_admin"))):
    conn = get_db()
    try:
        rows = conn.execute("SELECT id, email, role, mfa_enabled, created_at FROM users").fetchall()
        return {"users": [dict(r) for r in rows]}
    finally:
        conn.close()
