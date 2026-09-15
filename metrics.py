"""
UNG-TALOS — self-health metrics.

Same idea as OLYMPUS's own /metrics: a quick, admin-only answer to "is
this thing actually working right now" — not a general analytics
endpoint. In particular, this is how you'd notice the scheduler died
or a source has gone stale without digging through incidents.
"""
import time

from fastapi import APIRouter, Depends

from auth import CurrentUser, require_role
from db import get_db
from sources import SOURCES
from scheduler import POLL_INTERVAL_SECONDS

router = APIRouter(prefix="/metrics", tags=["metrics"])

_START_TIME = time.time()


@router.get("")
def get_metrics(admin: CurrentUser = Depends(require_role("security_admin"))):
    conn = get_db()
    try:
        users_total = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        incidents_open = conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='open'").fetchone()["c"]
        since_24h = time.time() - 86400
        incidents_last_24h = conn.execute(
            "SELECT COUNT(*) c FROM incidents WHERE detected_at >= ?", (since_24h,)
        ).fetchone()["c"]
        events_last_24h = conn.execute(
            "SELECT COUNT(*) c FROM ingested_events WHERE ingested_at >= ?", (since_24h,)
        ).fetchone()["c"]
        locked_out = conn.execute(
            "SELECT COUNT(*) c FROM login_attempts WHERE locked_until IS NOT NULL AND locked_until > ?",
            (time.time(),),
        ).fetchone()["c"]

        sources_out = []
        for name, source in SOURCES.items():
            row = conn.execute("SELECT * FROM source_health WHERE source_system=?", (name,)).fetchone()
            sources_out.append({
                "name": name,
                "configured": source.configured(),
                "last_poll_at": row["last_poll_at"] if row else None,
                "last_success_at": row["last_success_at"] if row else None,
                "last_error": row["last_error"] if row else None,
            })

        return {
            "uptime_seconds": round(time.time() - _START_TIME),
            "background_polling_enabled": POLL_INTERVAL_SECONDS > 0,
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            "users_total": users_total,
            "incidents_open": incidents_open,
            "incidents_last_24h": incidents_last_24h,
            "events_ingested_last_24h": events_last_24h,
            "accounts_currently_locked_out": locked_out,
            "sources": sources_out,
        }
    finally:
        conn.close()
