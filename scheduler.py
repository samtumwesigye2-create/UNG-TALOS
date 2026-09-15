"""
UNG-TALOS — background scheduler.

Stdlib-only periodic loop — no APScheduler or cron dependency. Runs the
same work POST /ingest/poll does, plus the event-retention prune, on a
timer so monitoring continues even if nobody has the dashboard open.

A non-blocking OS file lock elects one scheduler leader when multiple
application workers share the same host. Other workers serve HTTP but
do not start duplicate polling loops.
"""
import os
import threading
import time
import traceback

try:
    import fcntl
except ImportError:  # pragma: no cover - TALOS production target is Linux
    fcntl = None

POLL_INTERVAL_SECONDS = int(os.environ.get("TALOS_POLL_INTERVAL_SECONDS", str(5 * 60)))
SCHEDULER_LOCK_PATH = os.environ.get("TALOS_SCHEDULER_LOCK_PATH", "/tmp/ung-talos-scheduler.lock")

_started = False
_leader_lock = None


def acquire_leader_lock(path: str = SCHEDULER_LOCK_PATH):
    """Return an open lock file only when this process becomes leader."""
    if fcntl is None:
        return None
    lock_file = open(path, "a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_file
    except BlockingIOError:
        lock_file.close()
        return None


def release_leader_lock(lock_file) -> None:
    if lock_file is None:
        return
    if fcntl is not None:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    lock_file.close()


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
    """Start the periodic loop only in the elected scheduler process."""
    global _started, _leader_lock
    if _started or POLL_INTERVAL_SECONDS <= 0:
        return
    lock_file = acquire_leader_lock()
    if lock_file is None:
        return
    _leader_lock = lock_file
    _started = True
    t = threading.Thread(target=_loop, daemon=True, name="talos-scheduler")
    t.start()
