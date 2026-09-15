"""
UNG-TALOS — detection rules.

Runs over freshly-ingested events (see sources.py + main.py's ingest
loop) and raises incidents. Deliberately simple, threshold-based rules
to start — the same "rule-based, extend later" approach OLYMPUS's own
alerts.py takes from UNG-ORACLE.

Nothing here acts automatically on the watched system. A rule firing
creates an incident with a *suggested* action for a human to review —
see incidents.py for why containment stays human-approved in Phase 1.
"""
import time

from db import get_db
import integrity
import dlp
import notify

CRITICAL_KEYWORDS = ("locked out",)
BACKUP_CODE_KEYWORDS = ("backup code",)
REJECTED_DIRECTIVE_SPIKE_THRESHOLD = 3
REJECTED_DIRECTIVE_WINDOW_SECONDS = 30 * 60
COMPOSITE_RISK_THRESHOLD = 2

RESTRICTED_RULES = {
    "account_lockout", "mfa_backup_code_used", "accounts_locked_out",
    "dirty_word_match", "mass_activity", "off_hours_activity",
    "elevated_risk_actor",
}


def _raise_incident(conn, rule: str, severity: str, source_system: str, summary: str, suggested_action: str):
    existing = conn.execute(
        "SELECT id FROM incidents WHERE rule=? AND source_system=? AND summary=? AND status='open'",
        (rule, source_system, summary),
    ).fetchone()
    if existing:
        return None

    classification = "restricted" if rule in RESTRICTED_RULES else "internal"
    detected_at = time.time()
    fields = {
        "rule": rule, "severity": severity, "source_system": source_system, "summary": summary,
        "suggested_action": suggested_action, "classification": classification, "detected_at": detected_at,
    }
    prev_hash = integrity.get_last_hash(conn)
    record_hash = integrity.compute_hash(prev_hash, fields)

    conn.execute(
        "INSERT INTO incidents (rule, severity, source_system, summary, suggested_action, classification, "
        "status, detected_at, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        (rule, severity, source_system, summary, suggested_action, classification, detected_at, prev_hash, record_hash),
    )
    conn.commit()

    try:
        notify.notify(fields)
    except Exception:
        pass

    return True


def evaluate(conn, source_system: str, new_events: list[dict]) -> int:
    raised = 0
    actor_indicators: dict[str, set[str]] = {}

    def _mark(actor: str | None, tag: str):
        if actor:
            actor_indicators.setdefault(actor, set()).add(tag)

    for event in new_events:
        summary_lower = (event.get("summary") or "").lower()
        actor = event.get("actor_email")

        if event.get("severity") == "critical" or any(k in summary_lower for k in CRITICAL_KEYWORDS):
            if _raise_incident(
                conn, "account_lockout", "critical", source_system,
                f"{source_system}: {event['summary']}",
                f"Review {event.get('actor_email', 'the affected account')} in {source_system} — confirm this was the real "
                "account holder repeatedly mistyping a password, not a brute-force attempt.",
            ):
                raised += 1
            _mark(actor, "account_lockout")

        if any(k in summary_lower for k in BACKUP_CODE_KEYWORDS):
            if _raise_incident(
                conn, "mfa_backup_code_used", "warning", source_system,
                f"{source_system}: {event['summary']}",
                f"Confirm with {event.get('actor_email', 'the account holder')} that this backup-code login was expected. "
                "If not, treat the account as compromised: force a password reset and regenerate backup codes in "
                f"{source_system}.",
            ):
                raised += 1
            _mark(actor, "mfa_backup_code_used")

        hits = dlp.scan_for_dirty_words(event.get("summary", ""))
        if hits:
            if _raise_incident(
                conn, "dirty_word_match", "critical", source_system,
                f"{source_system}: event from {event.get('actor_email', 'unknown actor')} matched flagged term(s): {', '.join(hits)}",
                f"Review the full event in {source_system} and confirm whether flagged content was handled appropriately.",
            ):
                raised += 1
            _mark(actor, "dirty_word_match")

        if actor and dlp.is_off_hours(event.get("occurred_at", time.time())):
            if _raise_incident(
                conn, "off_hours_activity", "info", source_system,
                f"{source_system}: {event['actor_email']} active outside normal hours ({event.get('event_type', 'activity')})",
                "No action needed if this is expected (on-call, different timezone) — otherwise worth a quick check.",
            ):
                raised += 1
            _mark(actor, "off_hours_activity")

    for actor, count in dlp.mass_activity_actors(new_events).items():
        if _raise_incident(
            conn, "mass_activity", "warning", source_system,
            f"{source_system}: {actor} generated {count} events in {dlp.MASS_ACTIVITY_WINDOW_SECONDS // 60} minutes",
            f"Check what {actor} has been doing in {source_system} — a legitimate bulk operation, or worth a closer look.",
        ):
            raised += 1
        _mark(actor, "mass_activity")

    for actor, indicators in actor_indicators.items():
        if len(indicators) >= COMPOSITE_RISK_THRESHOLD:
            if _raise_incident(
                conn, "elevated_risk_actor", "critical", source_system,
                f"{source_system}: {actor} tripped {len(indicators)} independent indicators in one batch: "
                f"{', '.join(sorted(indicators))}",
                f"Multiple independent signals on the same account — review {actor}'s recent activity in "
                f"{source_system} now. This is a flag for a human to act on, not an automated lockout.",
            ):
                raised += 1

    now = time.time()
    recent_rejections = [
        e for e in new_events
        if e.get("event_type") == "directive_rejected" and e.get("occurred_at", 0) >= now - REJECTED_DIRECTIVE_WINDOW_SECONDS
    ]
    if len(recent_rejections) >= REJECTED_DIRECTIVE_SPIKE_THRESHOLD:
        if _raise_incident(
            conn, "rejected_directive_spike", "warning", source_system,
            f"{source_system}: {len(recent_rejections)} directives rejected in the last "
            f"{REJECTED_DIRECTIVE_WINDOW_SECONDS // 60} minutes",
            f"Review recent directive activity in {source_system} — check who issued them and whether the "
            "target subsystem/action combinations make sense.",
        ):
            raised += 1

    return raised


def evaluate_metrics(conn, source_system: str, metrics: dict | None) -> int:
    if not metrics:
        return 0
    raised = 0
    if metrics.get("accounts_currently_locked_out", 0) > 0:
        if _raise_incident(
            conn, "accounts_locked_out", "warning", source_system,
            f"{source_system}: {metrics['accounts_currently_locked_out']} account(s) currently locked out",
            f"Check {source_system}'s login activity for the locked-out account(s) before unlocking.",
        ):
            raised += 1
    if metrics.get("directives_pending_approval", 0) >= 5:
        if _raise_incident(
            conn, "approval_backlog", "info", source_system,
            f"{source_system}: {metrics['directives_pending_approval']} directives waiting on approval",
            f"A backlog of unapproved sensitive directives is building up in {source_system} — worth a look.",
        ):
            raised += 1
    return raised


def check_source_silence(conn, source_system: str, threshold_seconds: int) -> int:
    row = conn.execute("SELECT * FROM source_health WHERE source_system=?", (source_system,)).fetchone()
    if not row or row["last_success_at"] is None:
        return 0
    age = time.time() - row["last_success_at"]
    if age < threshold_seconds:
        return 0
    already_open = conn.execute(
        "SELECT id FROM incidents WHERE rule='source_silent' AND source_system=? AND status='open'",
        (source_system,),
    ).fetchone()
    if already_open:
        return 0
    if _raise_incident(
        conn, "source_silent", "critical", source_system,
        f"{source_system}: no successful poll in over {int(age // 60)} minutes"
        + (f" — last error: {row['last_error']}" if row["last_error"] else ""),
        f"Check whether {source_system} is reachable and TALOS's integrator credentials for it are still "
        "valid. This means TALOS itself may be blind right now, not just that things have been quiet.",
    ):
        return 1
    return 0