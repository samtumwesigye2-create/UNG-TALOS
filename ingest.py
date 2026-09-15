"""
UNG-TALOS — ingest loop.

Pulls new events from every configured source, stores them (deduplicated
on source_event_id), and runs the detection rules over whatever's new.
The actual work lives in run_poll_cycle() so it can be called both from
POST /ingest/poll (a person clicking the button) and from scheduler.py
(a background thread, so this keeps happening even if nobody has the
dashboard open).
"""
import os
import time

from fastapi import APIRouter, Depends

from auth import CurrentUser, get_current_user
from db import get_db
from sources import SOURCES
import rules

router = APIRouter(prefix="/ingest", tags=["ingest"])

SOURCE_SILENT_THRESHOLD_SECONDS = int(os.environ.get("TALOS_SOURCE_SILENT_THRESHOLD_SECONDS", str(60 * 60)))


def _record_source_health(conn, name: str, source) -> None:
    now = time.time()
    row = conn.execute("SELECT * FROM source_health WHERE source_system=?", (name,)).fetchone()
    last_success_at = row["last_success_at"] if row else None
    if getattr(source, "last_ok", None):
        last_success_at = now
    if row:
        conn.execute(
            "UPDATE source_health SET last_poll_at=?, last_success_at=?, last_error=? WHERE source_system=?",
            (now, last_success_at, getattr(source, "last_error", None), name),
        )
    else:
        conn.execute(
            "INSERT INTO source_health (source_system, last_poll_at, last_success_at, last_error) VALUES (?, ?, ?, ?)",
            (name, now, last_success_at, getattr(source, "last_error", None)),
        )
    conn.commit()


def run_poll_cycle() -> dict:
    conn = get_db()
    try:
        summary = {}
        for name, source in SOURCES.items():
            if not source.configured():
                summary[name] = {"configured": False}
                continue

            last_row = conn.execute(
                "SELECT MAX(occurred_at) AS m FROM ingested_events WHERE source_system=?", (name,)
            ).fetchone()
            since = last_row["m"] or 0

            fresh = source.fetch_new_events(since)
            stored = []
            for e in fresh:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ingested_events "
                    "(source_system, source_event_id, event_type, severity, summary, actor_email, sensitivity, occurred_at, ingested_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, e["id"], e["event_type"], e["severity"], e["summary"], e["actor_email"],
                     source.sensitivity, e["occurred_at"], time.time()),
                )
                if cur.rowcount:
                    stored.append(e)
            conn.commit()
            _record_source_health(conn, name, source)

            incidents_raised = rules.evaluate(conn, name, stored)
            metrics = source.fetch_metrics() if hasattr(source, "fetch_metrics") else None
            incidents_raised += rules.evaluate_metrics(conn, name, metrics)
            incidents_raised += rules.check_source_silence(conn, name, SOURCE_SILENT_THRESHOLD_SECONDS)

            summary[name] = {
                "configured": True, "new_events": len(stored), "incidents_raised": incidents_raised,
            }
        return summary
    finally:
        conn.close()


@router.post("/poll")
def poll(user: CurrentUser = Depends(get_current_user)):
    return run_poll_cycle()
