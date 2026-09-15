"""
UNG-TALOS — event sources.

TALOS never writes to a watched system and never uses a shared or
elevated credential — it logs in as an ordinary `integrator`-role user
on the watched system (same as any other UNG-ecosystem service
integration) and reads that system's own `/events` (and `/metrics`,
where available) endpoints. Read-only, least-privilege, exactly the
adapter pattern OLYMPUS itself uses against MERCURY/VECTOR — just
pointed the other direction.

Add a new source: subclass BaseSource, implement configured() and
fetch_new_events() (see OlympusSource below for the worked example),
and register an instance in SOURCES. Nothing else in this project
needs to change — ingest.py, rules.py, and metrics.py all work off
the SOURCES dict and the BaseSource contract.
"""
import os
import time

import requests

TIMEOUT = 5


class BaseSource:
    """Contract every source implements. `last_ok` / `last_error` are
    read by ingest.py after every fetch_new_events() call to update
    source_health — set them honestly (see OlympusSource) so a broken
    connection doesn't just look like a quiet day."""

    name: str = "unnamed"
    sensitivity: str = "internal"

    def __init__(self):
        self.last_ok: bool | None = None
        self.last_error: str | None = None

    def configured(self) -> bool:
        raise NotImplementedError

    def fetch_new_events(self, since: float) -> list[dict]:
        raise NotImplementedError

    def fetch_metrics(self) -> dict | None:
        return None


class OlympusSource(BaseSource):
    name = "UNG-OLYMPUS"
    sensitivity = "internal"

    def __init__(self):
        super().__init__()
        self.base_url = os.environ.get("OLYMPUS_URL", "").rstrip("/")
        self.email = os.environ.get("OLYMPUS_INTEGRATOR_EMAIL", "")
        self.password = os.environ.get("OLYMPUS_INTEGRATOR_PASSWORD", "")
        self._token = None
        self._token_expires_at = 0

    def configured(self) -> bool:
        return bool(self.base_url and self.email and self.password)

    def _get_token(self) -> str | None:
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        try:
            r = requests.post(
                f"{self.base_url}/auth/login",
                json={"email": self.email, "password": self.password},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            self._token = r.json()["access_token"]
            self._token_expires_at = time.time() + 7 * 3600
            return self._token
        except Exception as e:
            self._token = None
            self.last_error = f"auth failed: {e}"
            return None

    def fetch_new_events(self, since: float) -> list[dict]:
        if not self.configured():
            self.last_ok = None
            self.last_error = None
            return []
        token = self._get_token()
        if not token:
            self.last_ok = False
            return []
        try:
            r = requests.get(
                f"{self.base_url}/events",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 200},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            events = r.json().get("events", [])
            self.last_ok = True
            self.last_error = None
            return [
                {
                    "id": str(e["id"]),
                    "event_type": e.get("event_type"),
                    "severity": e.get("severity", "info"),
                    "summary": e.get("summary", ""),
                    "actor_email": e.get("actor_email"),
                    "occurred_at": e.get("occurred_at", time.time()),
                }
                for e in events if e.get("occurred_at", 0) >= since
            ]
        except Exception as e:
            self.last_ok = False
            self.last_error = str(e)[:200]
            return []

    def fetch_metrics(self) -> dict | None:
        token = self._get_token()
        if not token:
            return None
        try:
            r = requests.get(
                f"{self.base_url}/metrics",
                headers={"Authorization": f"Bearer {token}"},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            return r.json()
        except Exception:
            return None


SOURCES = {"UNG-OLYMPUS": OlympusSource()}
