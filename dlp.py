"""
UNG-TALOS — data loss prevention checks.

Two things that genuinely fit a log-watching monitoring tool:

1. Keyword/"dirty word" scanning over ingested event text — flags text
   containing configured sensitive terms (project codenames, etc.).
2. UEBA-lite: baseline-free, threshold-based behavioral checks (mass
   activity from one actor, activity outside configured hours) — the
   same "simple rule, extend later" approach as everything else here.

What's NOT here, and why: Content Disarm & Reconstruction and document-
marking enforcement need an actual file-transfer or document-generation
feature to apply to — TALOS doesn't have one, it watches text events.
Endpoint controls (USB lockdown, printer watermarking, thin-client
images) need an endpoint agent running on someone's device — out of
reach for a web service. Encrypted-traffic inspection, decryption
proxies, and anti-steganography scanning are network-appliance and
signal-processing engineering; a decryption proxy in particular is
TLS-interception infrastructure, which isn't something to hand out as
example code regardless of the defensive framing — see HANDOFF.md.
"""
import os
import time

DIRTY_WORDS = [w.strip().lower() for w in os.environ.get("TALOS_DIRTY_WORDS", "").split(",") if w.strip()]

MASS_ACTIVITY_THRESHOLD = 20
MASS_ACTIVITY_WINDOW_SECONDS = 10 * 60
OFF_HOURS_START = int(os.environ.get("TALOS_BUSINESS_HOURS_START", "6"))
OFF_HOURS_END = int(os.environ.get("TALOS_BUSINESS_HOURS_END", "20"))


def scan_for_dirty_words(text: str) -> list[str]:
    if not text or not DIRTY_WORDS:
        return []
    text_lower = text.lower()
    return [w for w in DIRTY_WORDS if w in text_lower]


def mass_activity_actors(events: list[dict], now: float | None = None) -> dict[str, int]:
    now = now or time.time()
    counts: dict[str, int] = {}
    for e in events:
        actor = e.get("actor_email")
        if not actor:
            continue
        if e.get("occurred_at", 0) >= now - MASS_ACTIVITY_WINDOW_SECONDS:
            counts[actor] = counts.get(actor, 0) + 1
    return {actor: c for actor, c in counts.items() if c >= MASS_ACTIVITY_THRESHOLD}


def is_off_hours(occurred_at: float) -> bool:
    hour = time.localtime(occurred_at).tm_hour
    if OFF_HOURS_START <= OFF_HOURS_END:
        return not (OFF_HOURS_START <= hour < OFF_HOURS_END)
    return not (hour >= OFF_HOURS_START or hour < OFF_HOURS_END)