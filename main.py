"""
UNG-TALOS — Phase 1 entrypoint.

Defense-only security monitoring for the UNG ecosystem: reads other
systems' own audit logs (starting with OLYMPUS), runs detection rules,
surfaces incidents with a human-approved suggested response. No
offensive capability, no autonomous action on a watched system's
accounts — see incidents.py for why.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from db import init_db
from auth import bootstrap_admin_if_empty
import auth_routes
import ingest
import incidents
import metrics
import scheduler

app = FastAPI(title="UNG-TALOS", version="0.1.0-phase1")

app.include_router(auth_routes.router)
app.include_router(auth_routes.users_router)
app.include_router(ingest.router)
app.include_router(incidents.router)
app.include_router(metrics.router)


@app.on_event("startup")
def on_startup():
    init_db()
    bootstrap_admin_if_empty()
    scheduler.start()


@app.get("/health")
def health():
    return {"status": "ok", "service": "UNG-TALOS", "phase": 1}


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def dashboard():
    return FileResponse("static/index.html")
