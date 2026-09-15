"""
UNG-TALOS — incident routes.

An incident is TALOS's own assessment (a rule fired). Containment in
Phase 1 is deliberately human-approved, not autonomous: an analyst
reviews the suggested action and marks the incident 'contained' once
they've actually done something about it (in the watched system itself
— TALOS has no write access there). Acting automatically on another
system's accounts from here would mean TALOS holds elevated
credentials in every system it watches, which is a bigger blast radius
than a monitoring tool should have by default.
"""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import CurrentUser, get_current_user, require_role
from db import get_db
from clearance import can_view
import integrity

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(user: CurrentUser = Depends(get_current_user), status_filter: str | None = None,
                    limit: int = 50, offset: int = 0):
    conn = get_db()
    try:
        q = "SELECT * FROM incidents"
        params = []
        if status_filter:
            q += " WHERE status=?"
            params.append(status_filter)
        q += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(q, params).fetchall()
        out = [dict(r) for r in rows if can_view(user.role, r["classification"])]
        return {"incidents": out, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.get("/integrity/verify")
def verify_integrity(admin: CurrentUser = Depends(require_role("security_admin"))):
    conn = get_db()
    try:
        return integrity.verify_chain(conn)
    finally:
        conn.close()


class HandleIn(BaseModel):
    note: str | None = None


def _transition(incident_id: int, new_status: str, user: CurrentUser, note: str | None):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        if not can_view(user.role, row["classification"]):
            raise HTTPException(status_code=403, detail="Insufficient clearance for this incident")
        conn.execute(
            "UPDATE incidents SET status=?, handled_by=?, handled_at=?, handling_note=? WHERE id=?",
            (new_status, user.email, time.time(), note, incident_id),
        )
        conn.commit()
        return {"id": incident_id, "status": new_status}
    finally:
        conn.close()


@router.post("/{incident_id}/acknowledge")
def acknowledge(incident_id: int, body: HandleIn, user: CurrentUser = Depends(get_current_user)):
    return _transition(incident_id, "acknowledged", user, body.note)


@router.post("/{incident_id}/contain")
def mark_contained(incident_id: int, body: HandleIn, user: CurrentUser = Depends(get_current_user)):
    return _transition(incident_id, "contained", user, body.note)


@router.post("/{incident_id}/dismiss")
def dismiss(incident_id: int, body: HandleIn, user: CurrentUser = Depends(get_current_user)):
    return _transition(incident_id, "dismissed", user, body.note)