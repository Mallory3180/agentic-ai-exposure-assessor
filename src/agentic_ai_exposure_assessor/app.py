"""FastAPI web UI + JSON API.

Browseable HTML lives at ``/`` (dashboard), ``/findings`` and ``/reports/latest``. The
remaining GET endpoints return JSON for programmatic use. POST endpoints drive the same
pipeline as the CLI (ingest config, ingest traces, assess) and redirect back to the
dashboard so the buttons in the UI work.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import config_loader, db, report, risk_engine, trace_ingest
from .report import _jinja_env, build_report_data

DEFAULT_FIXTURES = Path("fixtures")
DEFAULT_TRACE = Path("fixtures") / "otlp_trace_sample.json"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    db.init_db()
    yield


app = FastAPI(title="Agentic AI Exposure Assessor", version="0.1.0", lifespan=lifespan)


def _dashboard_data() -> dict[str, Any]:
    with db.session_scope() as session:
        data = build_report_data(session)
    scores = data.get("agent_scores", {})
    data["agent_scores_sorted"] = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return data


# --------------------------------------------------------------------------- #
# HTML pages                                                                   #
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    data = _dashboard_data()
    html = _jinja_env().get_template("dashboard.html").render(data=data)
    return HTMLResponse(html)


@app.get("/findings", response_class=HTMLResponse)
def findings_page() -> HTMLResponse:
    data = _dashboard_data()
    html = _jinja_env().get_template("finding.html").render(data=data)
    return HTMLResponse(html)


@app.get("/reports/latest", response_class=HTMLResponse)
def report_latest() -> HTMLResponse:
    with db.session_scope() as session:
        data = build_report_data(session)
    return HTMLResponse(report.render_html(data))


# --------------------------------------------------------------------------- #
# JSON API                                                                     #
# --------------------------------------------------------------------------- #
@app.get("/agents")
def get_agents() -> JSONResponse:
    return JSONResponse(_dashboard_data()["agents"])


@app.get("/tools")
def get_tools() -> JSONResponse:
    return JSONResponse(_dashboard_data()["tools"])


@app.get("/traces")
def get_traces() -> JSONResponse:
    data = _dashboard_data()
    return JSONResponse({"sequences": data["sequences"], "graphs": data["graphs"]})


@app.get("/owasp")
def get_owasp() -> JSONResponse:
    return JSONResponse(_dashboard_data()["owasp_mapping"])


@app.get("/api/findings")
def api_findings() -> JSONResponse:
    return JSONResponse(_dashboard_data()["findings"])


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
# Pipeline actions                                                             #
# --------------------------------------------------------------------------- #
@app.post("/ingest/config")
def ingest_config(fixtures: str = Query(default=str(DEFAULT_FIXTURES))) -> RedirectResponse:
    with db.session_scope() as session:
        config_loader.load_directory(Path(fixtures), session)
    return RedirectResponse("/", status_code=303)


@app.post("/ingest/traces")
def ingest_traces(file: str = Query(default=str(DEFAULT_TRACE))) -> RedirectResponse:
    with db.session_scope() as session:
        trace_ingest.ingest_file(Path(file), session)
    return RedirectResponse("/", status_code=303)


@app.post("/assess")
def assess() -> RedirectResponse:
    with db.session_scope() as session:
        risk_engine.assess(
            session,
            config_sources=[str(DEFAULT_FIXTURES)],
            trace_sources=[str(DEFAULT_TRACE)],
        )
    return RedirectResponse("/", status_code=303)


# --------------------------------------------------------------------------- #
# OTLP/HTTP live trace receiver                                                #
# --------------------------------------------------------------------------- #
@app.post("/v1/traces")
async def otlp_traces(request: Request) -> JSONResponse:
    """Receive OTLP/HTTP traces (JSON encoding) and ingest them live.

    Point an instrumented Agentic AI app's OpenTelemetry exporter (or an OpenTelemetry
    Collector) at this endpoint:

        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:8000/v1/traces
        OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json

    Spans are normalized and appended to the database; run an assessment afterwards. Only
    OTLP/JSON is supported in this MVP (not protobuf). Returns an OTLP success envelope.
    """
    if "json" not in (request.headers.get("content-type", "")).lower():
        return JSONResponse(
            {"error": "Only OTLP/JSON is supported (Content-Type: application/json)."},
            status_code=415,
        )
    try:
        doc = await request.json()
    except Exception as exc:  # malformed body
        return JSONResponse({"error": f"Invalid JSON body: {exc}"}, status_code=400)

    try:
        trace = trace_ingest.normalize_document(doc)
        with db.session_scope() as session:
            counts = trace_ingest.persist(trace, session, replace=False)
    except trace_ingest.TraceIngestError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    # OTLP success envelope (empty partialSuccess = fully accepted).
    return JSONResponse({"partialSuccess": {}, "ingested": counts})
