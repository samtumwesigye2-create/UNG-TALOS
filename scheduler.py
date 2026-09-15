"""
UNG-TALOS — background scheduler.

Stdlib-only periodic loop — no APScheduler or cron dependency. Runs the
same work POST /ingest/poll does, plus the event-retention prune, on a
timer so monitoring continues even if nobody has the dashboard open.
"""
import os
import threading
import time
import traceback

POLL_INTERVAL_SECONDS = int(os.environ.get("TALOS_POLL_INTERVAL_SECONDS", str(5 * 60)))

_started = False


def _loop():
    import ingest
    import retention
    while True:
        try:
            ingest.run_poll_cycle()
        except Exception:
            traceback.print_exc()
        try:
            retention.prune_old_events()
        except Exception:
            traceback.print_exc()
        time.sleep(POLL_INTERVAL_SECONDS)


def start() -> None:
    """Idempotent — safe to call once at startup. A no-op if
    TALOS_POLL_INTERVAL_SECONDS is set to 0."""
    global _started
    if _started or POLL_INTERVAL_SECONDS <= 0:
        return
    _started = True
    t = threading.Thread(target=_loop, daemon=True, name="talos-scheduler")
    t.start()
