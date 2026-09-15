"""
UNG-TALOS — outbound notifications.

Push, don't just wait for someone to open the dashboard. Two channels,
both optional and independently configured via environment variables.
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText

import requests

WEBHOOK_URL = os.environ.get("TALOS_WEBHOOK_URL", "")
MIN_SEVERITY = os.environ.get("TALOS_NOTIFY_MIN_SEVERITY", "critical")
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
SMTP_TO = os.environ.get("SMTP_TO", "")

TIMEOUT = 5


def _should_notify(severity: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(MIN_SEVERITY, 2)


def _send_webhook(incident: dict) -> None:
    if not WEBHOOK_URL:
        return
    payload = {
        "text": f"[TALOS] {incident['severity'].upper()} — {incident['rule']}: {incident['summary']}",
        "incident": incident,
    }
    requests.post(WEBHOOK_URL, json=payload, timeout=TIMEOUT)


def _send_email(incident: dict) -> None:
    if not (SMTP_HOST and SMTP_FROM and SMTP_TO):
        return
    body = (
        f"Rule: {incident['rule']}\n"
        f"Severity: {incident['severity']}\n"
        f"Source: {incident['source_system']}\n"
        f"Classification: {incident.get('classification', 'internal')}\n"
        f"Summary: {incident['summary']}\n"
        f"Suggested action: {incident.get('suggested_action') or '(none)'}\n"
        "\nThis is a flag for a human to review — TALOS does not act on the watched system automatically.\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[TALOS] {incident['severity'].upper()}: {incident['rule']}"
    msg["From"] = SMTP_FROM
    msg["To"] = SMTP_TO
    recipients = [a.strip() for a in SMTP_TO.split(",") if a.strip()]
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT) as server:
        server.starttls(context=ssl.create_default_context())
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, recipients, msg.as_string())


def notify(incident: dict) -> None:
    """Best-effort push for one incident. Never raises."""
    if not _should_notify(incident.get("severity", "info")):
        return
    try:
        _send_webhook(incident)
    except Exception:
        pass
    try:
        _send_email(incident)
    except Exception:
        pass
