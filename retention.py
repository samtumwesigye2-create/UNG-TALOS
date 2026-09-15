"""
UNG-TALOS — data retention.

Only ever prunes `ingested_events` (the raw feed TALOS pulled in) —
never `incidents`. Incidents are the hash-chained audit trail; deleting
an old incident would break every hash chained after it.
"""
import os
import time

from db import get_db

RETENTION_DAYS = int(os.environ.get("TALOS_EVENT_RETENTION_DAYS", "90"))


def prune_old_events() -> int:
    """Deletes ingested_events older than TALOS_EVENT_RETENTION_DAYS.
    Set that to 0 to disable pruning entirely."""
    if RETENTION_DAYS <= 0:
        return 0
    cutoff = time.time() - RETENTION_DAYS * 86400
    conn = get_db()
    try:
        cur = conn.execute("DELETE FROM ingested_events WHERE ingested_at < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
