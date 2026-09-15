"""
UNG-TALOS — tamper-evident hash chain for the incidents table.

Each incident's hash covers its own immutable creation fields plus the
previous incident's hash (classic hash-chain / "each block cites the
last" construction, using stdlib SHA3-256 — no external crypto library
needed or installed). Altering or deleting a past row breaks every hash
after it, and GET /integrity/verify will say exactly where the chain
first breaks.

What this is NOT: a distributed ledger. There is one SQLite file and
one writer process. A real DLT's guarantee comes from independent nodes
refusing to accept a rewritten history from each other — with a single
node, there's nothing external to cross-check against, so "blockchain"
would overstate what this provides. What it DOES provide: if someone
edits the database file directly (bypassing the API), that edit is
detectable on the next verify, because the hash won't match anymore.

Only creation-time fields are hashed. `status`/`handled_by`/`handled_at`/
`handling_note` are allowed to change after an incident is raised (that's
the whole point of acknowledge/contain/dismiss) — hashing those would
make every legitimate status update look like tampering. What's
protected is the historical record of *what was detected and when*,
not the current handling state.
"""
import hashlib
import json

GENESIS_HASH = "0" * 64

CHAINED_FIELDS = ("rule", "severity", "source_system", "summary", "suggested_action",
                   "classification", "detected_at")


def _canonical(fields: dict) -> str:
    return json.dumps({k: fields.get(k) for k in CHAINED_FIELDS}, sort_keys=True, default=str)


def compute_hash(prev_hash: str, fields: dict) -> str:
    payload = f"{prev_hash}|{_canonical(fields)}".encode()
    return hashlib.sha3_256(payload).hexdigest()


def get_last_hash(conn) -> str:
    row = conn.execute("SELECT record_hash FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
    return row["record_hash"] if row and row["record_hash"] else GENESIS_HASH


def verify_chain(conn) -> dict:
    rows = conn.execute("SELECT * FROM incidents ORDER BY id ASC").fetchall()
    expected_prev = GENESIS_HASH
    for row in rows:
        fields = dict(row)
        recomputed = compute_hash(expected_prev, fields)
        if row["prev_hash"] != expected_prev:
            return {"ok": False, "first_broken_id": row["id"], "reason": "prev_hash does not match the prior record's hash"}
        if row["record_hash"] != recomputed:
            return {"ok": False, "first_broken_id": row["id"], "reason": "stored hash does not match recomputed hash — record was altered after creation"}
        expected_prev = row["record_hash"]
    return {"ok": True, "checked": len(rows)}