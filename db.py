"""
UNG-TALOS — database layer.

Same stdlib-sqlite3 convention as the rest of the UNG ecosystem (see
UNG-OLYMPUS's db.py). TALOS is a defense-only security monitoring
system: it watches other UNG systems' own audit logs for signs of
trouble and surfaces incidents with a *suggested* response — it does
not reach into another system and act on its own.
"""
import sqlite3
import time
import os

DB_PATH = os.environ.get("TALOS_DB_PATH", "talos.db")

ROLES = ("security_admin", "analyst")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('security_admin','analyst')),
    mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_at REAL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    email TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    first_failed_at REAL,
    locked_until REAL
);

-- Raw security-relevant events pulled from watched systems' own /events
-- endpoints. TALOS never writes to a watched system, only reads its
-- audit log — same "adapter reads a subsystem's own API" pattern as
-- OLYMPUS uses against MERCURY/VECTOR. Ingestion is one-way by
-- construction: there is no code path in this project that writes back
-- to a source. `sensitivity` is a plain label (not an accreditation
-- claim) carried from the source, so if this ever sits behind a real
-- hardware boundary between domains, the software side is already
-- honest about which data came from where.
CREATE TABLE IF NOT EXISTS ingested_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_system TEXT NOT NULL,
    source_event_id TEXT,
    event_type TEXT,
    severity TEXT,
    summary TEXT,
    actor_email TEXT,
    sensitivity TEXT NOT NULL DEFAULT 'internal',
    occurred_at REAL,
    ingested_at REAL NOT NULL,
    UNIQUE(source_system, source_event_id)
);

-- A detection rule firing creates an incident. Distinct from a raw event:
-- an incident is TALOS's own assessment, with a suggested (not
-- automatic) response and a human-tracked resolution.
--
-- `classification` + ABAC: incidents that themselves reveal something
-- about account compromise (e.g. which account, what pattern) are marked
-- 'restricted' and only visible to security_admin — see clearance.py.
-- This is real attribute-based access control (clearance >= data's
-- classification), just with the one attribute this project actually
-- has (role-derived clearance) — not a claim of nationality/geofence
-- enforcement, which would need identity/location data this system
-- doesn't collect.
--
-- `record_hash`/`prev_hash`: a hash chain (see integrity.py) — each
-- incident's hash covers its own fields plus the previous incident's
-- hash, so altering or deleting a past row breaks every hash after it.
-- This is a single-instance tamper-evident log, not a distributed
-- ledger — there's one SQLite file and one writer, so there's nothing
-- for a second node to cross-check against. Call it what it is.
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    source_system TEXT NOT NULL,
    summary TEXT NOT NULL,
    suggested_action TEXT,
    classification TEXT NOT NULL DEFAULT 'internal',  -- 'internal' | 'restricted'
    status TEXT NOT NULL DEFAULT 'open',  -- 'open' | 'acknowledged' | 'contained' | 'dismissed'
    detected_at REAL NOT NULL,
    handled_by TEXT,
    handled_at REAL,
    handling_note TEXT,
    prev_hash TEXT,
    record_hash TEXT
);

-- One row per configured source: when TALOS last *attempted* a poll
-- vs. when it last *succeeded*. These can diverge — that gap is exactly
-- how rules.check_source_silence() tells "source is quiet" apart from
-- "TALOS can't actually reach it anymore" (see sources.py).
CREATE TABLE IF NOT EXISTS source_health (
    source_system TEXT PRIMARY KEY,
    last_poll_at REAL,
    last_success_at REAL,
    last_error TEXT
);
"""


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
