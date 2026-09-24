"""HTTP API. Runs unchanged under uvicorn locally and on Lambda via AWS Lambda Web Adapter."""

import logging
import time
import uuid
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .enrich import Enricher, exploit_data_errors
from .obs import emit_metrics, log_event, setup_logging
from .parsers import ParseError
from .scoring import PRIORITIES, analyze
from .store import Store

MAX_BODY = 4 * 1024 * 1024  # API Gateway base64-encodes bodies; Lambda's sync payload limit is 6 MB
SITE_DIR = Path(__file__).parent / "site"
CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"

setup_logging()
log = logging.getLogger("vulnprio.api")
app = FastAPI(title="vulnprio", version="0.1.0", description="Rank vulnerability findings by exploitation risk.")


@cache
def get_store() -> Store:
    return Store()


@cache
def get_enricher() -> Enricher:
    return Enricher()


@app.middleware("http")
async def access_log(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex  # client-supplied: bound it
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
    finally:
        log_event(
            log,
            "request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=status,
            duration_ms=round((time.perf_counter() - start) * 1000, 1),
        )
    response.headers["x-request-id"] = request_id
    response.headers["content-security-policy"] = CSP
    response.headers["x-content-type-options"] = "nosniff"
    return response


async def _read_body(request: Request) -> bytes:
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        raise HTTPException(413, f"body exceeds {MAX_BODY} bytes; gzip it or split the scan")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            raise HTTPException(413, f"body exceeds {MAX_BODY} bytes; gzip it or split the scan")
    return bytes(body)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/scans", status_code=201)
async def create_scan(
    request: Request,
    store: Annotated[Store, Depends(get_store)],
    enricher: Annotated[Enricher, Depends(get_enricher)],
    name: Annotated[str | None, Query(max_length=128)] = None,
):
    """Upload raw Trivy/Grype JSON, SARIF, or CSV (optionally gzipped) as the request body."""
    raw = await _read_body(request)
    start = time.perf_counter()
    try:
        # ponytail: sync enrichment in the request path; move to S3-event worker if scans outgrow the 30 s limit
        # Blocking httpx/boto3 calls run in a thread so one ingest doesn't stall /healthz under uvicorn.
        report, errors, summary = await run_in_threadpool(analyze, raw, enricher)
    except ParseError as e:
        raise HTTPException(400, str(e)) from None
    scan_id = uuid.uuid4().hex
    meta = {
        "scan_id": scan_id,
        "name": name or report.artifact or "unnamed",
        "artifact": report.artifact,
        "format": report.format,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "summary": summary,
        "enrichment_errors": errors,
        "kev_catalog_version": enricher.kev_version,
    }
    await run_in_threadpool(store.save_scan, meta, report.findings, raw)
    duration = time.perf_counter() - start
    log_event(log, "scan ingested", scan_id=scan_id, format=report.format, **summary)
    emit_metrics(
        {
            "ScansIngested": (1, "Count"),
            "FindingsIngested": (summary["total"], "Count"),
            "ActNowFindings": (summary["act_now"], "Count"),
            "EnrichmentErrors": (len(exploit_data_errors(errors)), "Count"),  # SLI 4: KEV/EPSS only
            "IngestDuration": (round(duration * 1000, 1), "Milliseconds"),
        }
    )
    return meta


@app.get("/scans")
def list_scans(store: Annotated[Store, Depends(get_store)], limit: Annotated[int, Query(ge=1, le=100)] = 50):
    return {"scans": store.list_scans(limit)}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, store: Annotated[Store, Depends(get_store)]):
    if not (meta := store.get_scan(scan_id)):
        raise HTTPException(404, "scan not found")
    return meta


@app.get("/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    store: Annotated[Store, Depends(get_store)],
    priority: Annotated[str | None, Query(pattern="^P[1-4]$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
):
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan not found")
    try:
        findings, next_cursor = store.get_findings(scan_id, priority, limit, cursor)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"findings": findings, "next": next_cursor, "priorities": PRIORITIES}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


# Local-dev dashboard; the same page is published to GitHub Pages with precomputed data.
app.mount("/ui", StaticFiles(directory=SITE_DIR, html=True), name="ui")
