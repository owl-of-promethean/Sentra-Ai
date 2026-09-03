"""
Sentra AI
AI-Assisted Security Operations Center System

Pipeline overview:

    Security Logs
          |
    POST /logs
          |
    In-memory storage
          |
    10-second window
          |
    Generic investigation trigger
          |
    Knowledge retrieval
          |
    Groq LLM analysis  (background task)
          |
    SecurityFinding

Audit pipeline (Phase 3 — Authorized Application model):

    SOC Analyst  →  POST /auth/login
                →  GET  /applications
                →  POST /audit/request  { app_id, scan_type, scope_id, endpoint }
                    Backend resolves app_id → trusted source_path
                →  GET  /audit/{audit_id}   (poll until complete)
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware

from app.config import Config
from app.log_processor import get_log_processor
from app.llm import analyze_investigation
from app.audit_schemas import AuditRequest, AuditResult, make_display_id
from app.history import get_history_store
from app.auth import LoginRequest, LoginResponse, require_auth, validate_credentials, _create_access_token, _TOKEN_EXPIRE_HOURS
from app.authorized_apps import get_authorized_app, list_authorized_apps, validate_scope
from app.advanced_ai.routes import router as advanced_ai_router


# ==============================================================
# IN-MEMORY AUDIT STORE
# (keyed by audit_id UUID string)
# ==============================================================

_audits: dict[str, dict] = {}


# ==============================================================
# BACKGROUND AUDIT RUNNER
# ==============================================================

async def _run_audit_engine(audit_id: str, investigation: Optional[dict], scan_type: str = "quick") -> None:
    """
    Run an audit scan in the background.

    Retrieves the AuditResult from _audits by audit_id, runs the
    synchronous engine inside run_in_executor so it doesn't block the
    event loop, then updates _audits and the history store in-place.

    Dispatches to run_quick_scan or run_deep_scan based on scan_type.

    A failed engine run must never remove the audit record.
    """
    audit_data = _audits.get(audit_id)
    if audit_data is None:
        print(f"  [Audit] WARNING: audit_id {audit_id} not found in store")
        return

    scan_label = scan_type.capitalize()
    print(f"  [Audit] Starting {scan_label} Scan for audit {audit_id} ...")

    # Rebuild an AuditResult from the stored dict
    from app.audit_schemas import AuditResult as _AR
    try:
        audit_result = _AR(**audit_data)
    except Exception as exc:
        print(f"  [Audit] Failed to deserialize AuditResult: {exc}")
        return

    # For deep scans, wait briefly for investigation Gemini analysis
    # so the audit prompt has the SOC finding available.
    if scan_type == "deep" and investigation is not None:
        inv_status = investigation.get("status", "")
        if inv_status in ("triggered", "knowledge_ready"):
            print(f"  [Audit] Deep scan: waiting up to 30s for investigation analysis ...")
            for _ in range(60):  # poll every 500ms for up to 30s
                if investigation.get("status") in ("analyzed", "analysis_failed"):
                    break
                await asyncio.sleep(0.5)
            print(f"  [Audit] Investigation status after wait: {investigation.get('status')}")

    loop = asyncio.get_event_loop()

    def _sync_run():
        from app.audit_engine import AuditEngine
        engine = AuditEngine()
        if scan_type == "deep":
            return engine.run_deep_scan(audit_result, investigation)
        return engine.run_quick_scan(audit_result, investigation)

    try:
        updated = await loop.run_in_executor(None, _sync_run)
    except Exception as exc:
        audit_data["status"] = "failed"
        audit_data["error"]  = f"Executor error: {exc}"
        _audits[audit_id] = audit_data
        print(f"  [Audit] Executor error for {audit_id}: {exc}")
        return

    # Persist the updated result back into the in-memory store
    updated_dict = updated.model_dump(mode="json")
    _audits[audit_id] = updated_dict

    # Update history
    try:
        get_history_store().update_audit_entry(updated)
    except Exception as exc:
        print(f"  [Audit] Failed to update history for {audit_id}: {exc}")

    finding_count = len(updated.findings)
    print(
        f"  [Audit] Done {audit_id} — "
        f"status={updated.status}  findings={finding_count}"
    )


# ==============================================================
# BACKGROUND LLM ANALYSIS
# ==============================================================

async def _run_gemini_analysis(investigation: dict) -> None:
    """
    Analyse a triggered investigation with the LLM (Groq) in the background.

    Runs via run_in_executor so the synchronous HTTP call does
    not block the asyncio event loop or the /logs ingestion endpoint.

    Mutates the investigation dict in-place:
      On success : status = "analyzed",        finding = <SecurityFinding dict>
      On failure : status = "analysis_failed", finding = {"error": ...}
    """
    inv_id = investigation.get("id", "unknown")
    print(f"  [LLM] Analysing investigation {inv_id} ...")

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None,
            analyze_investigation,
            investigation,
        )
    except Exception as exc:
        result = {"success": False, "error": f"Executor error: {exc}"}

    if result.get("success"):
        investigation["status"]  = "analyzed"
        investigation["finding"] = result["finding"]
        severity   = result["finding"].get("severity", "?")
        confidence = result["finding"].get("confidence", "?")
        print(
            f"  [LLM] Done {inv_id} — "
            f"severity={severity}  confidence={confidence}"
        )
    else:
        _error_msg = result.get("error", "unknown error")
        investigation["status"]  = "analysis_failed"
        investigation["finding"] = {
            "error":        _error_msg,
            "summary":      f"Analysis failed: {_error_msg}",
            "raw_response": result.get("raw_response", ""),
        }
        print(
            f"  [LLM] Failed {inv_id}: "
            f"{_error_msg}"
        )
        _raw = result.get("raw_response", "")
        if _raw:
            print(f"  [LLM] Raw response (first 200 chars): {str(_raw)[:200]}")

    try:
        get_history_store().update_soc_entry(investigation)
    except Exception as exc:
        print(f"  [History] Failed to update SOC entry for {inv_id}: {exc}")


async def periodic_window_processing():
    """
    Process one completed 10-second window at a time.
    """
    processor = get_log_processor()

    while True:
        await asyncio.sleep(processor.window_seconds // 2)

        result = processor.process_completed_window()

        print()
        print("=" * 60)
        print("WINDOW PROCESSING SUMMARY")
        print("=" * 60)
        print(f"Window: {result['window_start']} → {result['window_end']}")
        print(f"Logs received: {result['log_count']}")
        print(f"Investigation trigger: {result['should_investigate']}")

        if result.get("trigger_score", 0) > 0:
            print(f"Trigger score: {result['trigger_score']}")
            reasons = result.get("trigger_reasons", [])
            if reasons:
                print(f"Reasons: {', '.join(reasons)}")

        investigation = processor.handle_investigation_trigger(result)

        if investigation:
            print()
            print("=" * 60)
            print("INVESTIGATION CREATED")
            print("=" * 60)
            print(f"ID: {investigation['id']}")
            print(f"Window: {investigation['window_start']} -> {investigation['window_end']}")
            print(f"Logs: {investigation['log_count']}")
            print(f"Trigger score: {investigation['trigger_score']}")
            if investigation['trigger_reasons']:
                print(f"Reasons: {', '.join(investigation['trigger_reasons'])}")
            kc_status = investigation.get("knowledge_context", {}).get("status", "unknown")
            print(f"Knowledge context: {kc_status}")
            print(f"Status: {investigation['status']}")
            print("=" * 60)
            print()

            try:
                get_history_store().add_soc_entry(investigation)
            except Exception as exc:
                print(f"  [History] Failed to add SOC entry: {exc}")

            asyncio.create_task(_run_gemini_analysis(investigation))

        print("=" * 60)
        print()


# ==============================================================
# APPLICATION LIFESPAN
# ==============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print()
    print("Starting Sentra AI...")
    print("10-second log processing windows enabled.")

    background_task = asyncio.create_task(periodic_window_processing())

    yield

    print("Shutting down Sentra AI...")
    background_task.cancel()
    try:
        await background_task
    except asyncio.CancelledError:
        pass


# ==============================================================
# FASTAPI APPLICATION
# ==============================================================

app = FastAPI(
    title="Sentra AI",
    description="AI-Assisted Security Operations Center System",
    version="0.2.0",
    lifespan=lifespan
)


# ==============================================================
# CORS
# ==============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================
# ROOT  (public)
# ==============================================================

@app.get("/")
async def root():
    """Basic system status."""
    return {
        "status":  "running",
        "service":  "Sentra AI",
        "version": "0.2.0",
        "message": "AI-Assisted SOC Analyst System",
    }


# ==============================================================
# HEALTH  (public)
# ==============================================================

@app.get("/health")
async def health_check():
    """Check basic configuration."""
    try:
        Config.validate()
        return {"status": "healthy", "configuration": "valid"}
    except ValueError as exc:
        return {"status": "degraded", "configuration": "invalid", "error": str(exc)}


# ==============================================================
# AUTH — POST /auth/login  (public)
# ==============================================================

@app.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """
    Authenticate a SOC analyst.

    Credentials are compared against SOC_ANALYST_EMAIL and
    SOC_ANALYST_PASSWORD environment variables.

    Returns a short-lived Bearer token on success.

    Request body:
        { "email": "...", "password": "..." }

    Response:
        { "access_token": "...", "token_type": "bearer", "expires_in": <seconds> }
    """
    if not validate_credentials(body.email, body.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = _create_access_token(subject=body.email.lower().strip())
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=_TOKEN_EXPIRE_HOURS * 3600,
    )


# ==============================================================
# AUTHORIZED APPLICATIONS — GET /applications  (protected)
# ==============================================================

@app.get("/applications")
async def list_applications(analyst: str = Depends(require_auth)):
    """
    Return all authorized customer applications available to the analyst.

    Only active applications are returned.
    Internal filesystem paths (source_path) are excluded from the response.

    Requires: Bearer token from POST /auth/login.
    """
    apps = list_authorized_apps()
    return {
        "count":        len(apps),
        "applications": [a.to_frontend_dict() for a in apps],
    }


# ==============================================================
# LOG INGESTION  (public — log sources are not authenticated)
# ==============================================================

@app.post("/logs")
async def ingest_log(log_data: dict):
    """
    Receive one security log.

    Required fields: timestamp, source_ip, method, path, status, user_agent
    """
    required_fields = ["timestamp", "source_ip", "method", "path", "status", "user_agent"]
    missing_fields = [f for f in required_fields if f not in log_data]

    if missing_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Missing required fields", "fields": missing_fields},
        )

    processor = get_log_processor()
    ingested_log = processor.ingest_log(log_data)

    return {
        "status":    "ingested",
        "log_id":    ingested_log["log_id"],
        "timestamp": ingested_log["timestamp"],
        "source_ip": ingested_log["source_ip"],
    }


# ==============================================================
# CURRENT WINDOW  (public)
# ==============================================================

@app.get("/logs/window")
async def get_current_window():
    """Return logs currently inside the active 10-second window."""
    processor = get_log_processor()
    logs = processor.get_logs_for_current_window()
    return {
        "window_seconds": processor.window_seconds,
        "log_count":      len(logs),
        "logs":           logs,
    }


# ==============================================================
# STATS  (public)
# ==============================================================

@app.get("/logs/stats")
async def get_stats():
    """Return basic in-memory statistics."""
    processor = get_log_processor()
    all_logs     = processor.get_all_logs()
    current_logs = processor.get_logs_for_current_window()
    return {
        "total_logs_ingested":     len(all_logs),
        "logs_in_current_window":  len(current_logs),
        "window_seconds":          processor.window_seconds,
    }


# ==============================================================
# MANUAL WINDOW PROCESSING  (public)
# ==============================================================

@app.post("/logs/process")
async def process_window():
    """Manually process the latest completed window (development/testing)."""
    processor = get_log_processor()
    result = processor.process_completed_window()
    return {
        "window_start":    result["window_start"],
        "window_end":      result["window_end"],
        "log_count":       result["log_count"],
        "should_investigate": result["should_investigate"],
        "status":          result["status"],
    }


# ==============================================================
# INVESTIGATIONS LIST  (protected)
# ==============================================================

@app.get("/investigations")
async def list_investigations(analyst: str = Depends(require_auth)):
    """Return all investigations currently stored in memory.

    Includes a display_id, trigger_reasons, finding summary (if analyzed),
    and up to 5 sample logs so the SOC dashboard can render without
    fetching each investigation individually.
    """
    processor = get_log_processor()
    investigations = processor.get_all_investigations()
    summaries = []
    for inv in investigations:
        inv_id = inv["id"]
        if "display_id" not in inv:
            inv["display_id"] = make_display_id(inv_id)
        # Include finding if available (may be None / error)
        finding = inv.get("finding")
        if isinstance(finding, dict) and "error" in finding:
            finding = None  # don't expose error objects
        summaries.append({
            "id":              inv_id,
            "display_id":      inv["display_id"],
            "window_start":    inv.get("window_start"),
            "window_end":      inv.get("window_end"),
            "log_count":       inv.get("log_count", 0),
            "trigger_score":   inv.get("trigger_score", 0),
            "trigger_reasons": inv.get("trigger_reasons", []),
            "status":          inv.get("status"),
            "finding":         finding,
            # Sample logs for SOC event display (source_ip, path)
            "logs":            inv.get("logs", [])[:5],
        })
    return {"count": len(summaries), "investigations": summaries}


# ==============================================================
# INVESTIGATION DETAIL  (protected)
# ==============================================================

@app.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    analyst: str = Depends(require_auth),
):
    """Return the full detail of one investigation by ID."""
    processor = get_log_processor()
    for inv in processor.get_all_investigations():
        if inv["id"] == investigation_id:
            if "display_id" not in inv:
                inv["display_id"] = make_display_id(inv["id"])
            return inv

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"message": "Investigation not found", "id": investigation_id},
    )


# ==============================================================
# AUDIT REQUEST  (protected)
# ==============================================================

@app.post("/audit/request", status_code=status.HTTP_201_CREATED)
async def request_audit(
    body: AuditRequest,
    analyst: str = Depends(require_auth),
):
    """
    Submit a code-audit request against an authorized application.

    Security contract:
      - app_id must identify a known, active authorized application.
      - scan_type must be 'quick' or 'deep'.
      - scope_id must be permitted for that application.
      - endpoint (when provided) must be in the application's allowed paths.
      - Arbitrary filesystem paths or URLs submitted by the client are ignored.
      - The backend resolves app_id -> trusted source_path internally.

    Request body:
        {
          "investigation_id": "<UUID>",
          "app_id":           "app_demoshop",
          "scan_type":        "quick",
          "scope_id":         "application",
          "endpoint":         null
        }

    Returns:
        audit_id, display_id, investigation_id, investigation_display_id,
        app_id, app_name, app_website, environment, scan_type, scope_id,
        scope_endpoint, status, created_at
    """
    processor = get_log_processor()

    # 1. Verify the investigation exists.
    target_inv = None
    for inv in processor.get_all_investigations():
        if inv["id"] == body.investigation_id:
            target_inv = inv
            break

    if target_inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "message": "Investigation not found",
                "investigation_id": body.investigation_id,
            },
        )

    # 2. Resolve and validate the authorized application.
    authorized_app = get_authorized_app(body.app_id)
    if authorized_app is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": (
                    "Unknown or inactive application. "
                    "Only authorized applications may be audited."
                ),
                "app_id": body.app_id,
            },
        )

    # 3. Validate the requested scope and endpoint.
    scope_error = validate_scope(authorized_app, body.scope_id, body.endpoint)
    if scope_error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": scope_error},
        )

    # 4. Resolve the INTERNAL source path — never trust the client for this.
    internal_source_path = os.path.abspath(authorized_app.source_path)

    # 5. Build the audit record.
    inv_display_id = target_inv.get("display_id") or make_display_id(body.investigation_id)

    audit = AuditResult(
        investigation_id=body.investigation_id,
        investigation_display_id=inv_display_id,
        source_path=internal_source_path,   # internal — resolved server-side
        app_id=authorized_app.app_id,
        app_name=authorized_app.name,
        app_website=authorized_app.website,
        environment=authorized_app.environment,
        scan_type=body.scan_type,
        scope_id=body.scope_id,
        scope_endpoint=body.endpoint,
        status="pending",
    )

    # 6. Store in memory.
    _audits[audit.audit_id] = audit.model_dump(mode="json")

    # 7. Persist in history.
    try:
        get_history_store().add_audit_entry(audit)
    except Exception as exc:
        print(f"  [History] Failed to add audit entry: {exc}")

    # 8. Launch scan (dispatched by scan_type).
    asyncio.create_task(_run_audit_engine(audit.audit_id, target_inv, scan_type=body.scan_type))

    message = (
        f"{body.scan_type.capitalize()} Scan started in background for "
        f"'{authorized_app.name}' (scope: {body.scope_id})."
    )

    return {
        "audit_id":                  audit.audit_id,
        "display_id":                audit.display_id,
        "investigation_id":          audit.investigation_id,
        "investigation_display_id":  audit.investigation_display_id,
        "app_id":                    audit.app_id,
        "app_name":                  audit.app_name,
        "app_website":               audit.app_website,
        "environment":               audit.environment,
        "scan_type":                 audit.scan_type,
        "scope_id":                  audit.scope_id,
        "scope_endpoint":            audit.scope_endpoint,
        "status":                    audit.status,
        "created_at":                audit.created_at.isoformat(),
        "message":                   message,
    }


# ==============================================================
# AUDIT STATUS / RESULT  (protected)
# ==============================================================

@app.get("/audit/{audit_id}")
async def get_audit(
    audit_id: str,
    analyst: str = Depends(require_auth),
):
    """
    Return the current status and result of a code audit.

    Status transitions: pending -> analyzing -> complete / failed

    Returns all public AuditResult fields.
    source_path is excluded from the response (internal implementation detail).
    """
    audit_data = _audits.get(audit_id)

    if audit_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Audit not found", "audit_id": audit_id},
        )

    # Return a copy that excludes the internal source_path.
    public_data = {k: v for k, v in audit_data.items() if k != "source_path"}
    return public_data


# ==============================================================
# INVESTIGATION → AUDIT CONVENIENCE  (protected)
# ==============================================================

@app.get("/investigations/{investigation_id}/audit")
async def get_investigation_audit(
    investigation_id: str,
    analyst: str = Depends(require_auth),
):
    """Return the audit record linked to a specific investigation (if any)."""
    for audit_data in _audits.values():
        if audit_data.get("investigation_id") == investigation_id:
            public_data = {k: v for k, v in audit_data.items() if k != "source_path"}
            return public_data

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "message": "No audit found for this investigation",
            "investigation_id": investigation_id,
        },
    )


# ==============================================================
# LIVE LOGS — LIST  (protected)
# ==============================================================

@app.get("/logs/list")
async def list_logs(
    analyst: str = Depends(require_auth),
    event_type: Optional[str] = Query(
        default=None,
        description="Filter by event_type field (case-insensitive substring match).",
    ),
    method: Optional[str] = Query(
        default=None,
        description="HTTP method filter (e.g. GET, POST).",
    ),
    status_range: Optional[str] = Query(
        default=None,
        alias="status",
        description="HTTP status range: 2xx, 3xx, 4xx, 5xx, or an exact integer.",
    ),
    search: Optional[str] = Query(
        default=None,
        description=(
            "Case-insensitive substring search across source_ip, path, "
            "user_agent, and event_type fields."
        ),
    ),
    limit: int = Query(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of logs to return (newest first).",
    ),
):
    """
    Return raw security logs with optional filtering.

    Newest logs are returned first.

    Filters are AND-combined:
      - event_type: substring match (case-insensitive) on the log's event_type field.
      - method:     exact match (case-insensitive) on HTTP method.
      - status:     range group (2xx/3xx/4xx/5xx) or exact integer.
      - search:     substring match across source_ip, path, user_agent, event_type.

    Requires: Bearer token from POST /auth/login.
    """
    processor = get_log_processor()
    logs = processor.get_all_logs()

    # Apply filters
    filtered = _filter_logs(logs, event_type=event_type, method=method,
                             status_range=status_range, search=search)

    # Newest first, then limit
    filtered = list(reversed(filtered))[:limit]

    return {
        "count": len(filtered),
        "logs": filtered,
    }


# ==============================================================
# LIVE LOGS — EXPORT  (protected)
# ==============================================================

@app.get("/logs/export")
async def export_logs(
    analyst: str = Depends(require_auth),
    fmt: str = Query(
        default="json",
        alias="format",
        description="Export format: json or csv.",
    ),
    from_ts: Optional[str] = Query(
        default=None,
        alias="from",
        description="ISO 8601 start timestamp (inclusive).",
    ),
    to_ts: Optional[str] = Query(
        default=None,
        alias="to",
        description="ISO 8601 end timestamp (inclusive).",
    ),
    event_type: Optional[str] = Query(default=None),
    method: Optional[str] = Query(default=None),
    status_range: Optional[str] = Query(
        default=None,
        alias="status",
    ),
    search: Optional[str] = Query(default=None),
):
    """
    Export security logs as JSON or CSV.

    Applies the same filters as GET /logs/list plus optional timeframe filtering.

    Parameters:
      - format:     json (default) or csv.
      - from:       ISO 8601 start timestamp.
      - to:         ISO 8601 end timestamp.
      - event_type, method, status, search: same as /logs/list.

    Requires: Bearer token from POST /auth/login.
    """
    import csv as _csv
    import io

    if fmt.lower() not in ("json", "csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "format must be 'json' or 'csv'"},
        )

    processor = get_log_processor()
    logs = processor.get_all_logs()

    # Timeframe filter
    if from_ts or to_ts:
        logs = _filter_by_timeframe(logs, from_ts, to_ts)

    # Field filters
    logs = _filter_logs(logs, event_type=event_type, method=method,
                         status_range=status_range, search=search)

    # Newest first
    logs = list(reversed(logs))

    if fmt.lower() == "csv":
        output = io.StringIO()
        fields = ["log_id", "ingested_at", "timestamp", "source_ip", "method",
                  "path", "status", "user_agent", "event_type"]
        writer = _csv.DictWriter(
            output,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for log in logs:
            writer.writerow({f: log.get(f, "") for f in fields})
        content = output.getvalue()
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=logs_export.csv"},
        )

    # JSON export
    import json as _json
    content = _json.dumps({"count": len(logs), "logs": logs}, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=logs_export.json"},
    )


# ==============================================================
# LOG FILTER HELPERS (used by /logs/list and /logs/export)
# ==============================================================

def _filter_logs(
    logs: list,
    *,
    event_type: Optional[str] = None,
    method: Optional[str] = None,
    status_range: Optional[str] = None,
    search: Optional[str] = None,
) -> list:
    """Apply field-level filters to a list of raw log dicts."""
    result = logs

    if event_type:
        et_lower = event_type.lower()
        result = [l for l in result if et_lower in str(l.get("event_type", "")).lower()]

    if method:
        m_upper = method.upper()
        result = [l for l in result if str(l.get("method", "")).upper() == m_upper]

    if status_range:
        result = [l for l in result if _matches_status(l.get("status"), status_range)]

    if search:
        s_lower = search.lower()
        result = [
            l for l in result
            if (
                s_lower in str(l.get("source_ip", "")).lower()
                or s_lower in str(l.get("path", "")).lower()
                or s_lower in str(l.get("user_agent", "")).lower()
                or s_lower in str(l.get("event_type", "")).lower()
            )
        ]

    return result


def _matches_status(log_status, status_range: str) -> bool:
    """Return True if log_status matches the status_range spec."""
    try:
        code = int(log_status)
    except (TypeError, ValueError):
        return False

    range_lower = status_range.lower()
    if range_lower == "2xx":
        return 200 <= code < 300
    if range_lower == "3xx":
        return 300 <= code < 400
    if range_lower == "4xx":
        return 400 <= code < 500
    if range_lower == "5xx":
        return code >= 500

    # Exact integer match
    try:
        return code == int(status_range)
    except ValueError:
        return False


def _filter_by_timeframe(
    logs: list,
    from_ts: Optional[str],
    to_ts: Optional[str],
) -> list:
    """Filter logs by ingested_at timestamp."""
    from datetime import datetime, timezone as _tz

    def _parse(ts: str) -> Optional[datetime]:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz.utc)
            return dt
        except ValueError:
            return None

    from_dt = _parse(from_ts) if from_ts else None
    to_dt   = _parse(to_ts)   if to_ts   else None

    if from_dt is None and to_dt is None:
        return logs

    result = []
    for log in logs:
        raw = log.get("ingested_at") or log.get("timestamp")
        if not raw:
            continue
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz.utc)
        except ValueError:
            continue
        if from_dt and dt < from_dt:
            continue
        if to_dt and dt > to_dt:
            continue
        result.append(log)
    return result


# ==============================================================
# HISTORY  (protected)
# ==============================================================

@app.get("/history")
async def get_history(
    analyst: str = Depends(require_auth),
    q: Optional[str] = Query(
        default=None,
        description=(
            "Optional search query. Case-insensitive substring match against "
            "investigation ID, display ID, scan type, severity, activity type, "
            "trigger reasons, and audit metadata."
        ),
    ),
):
    """
    Return combined SOC + audit history, newest first.

    Supports local search via ?q=<query>.

    Returns:
        { "count": N, "query": "...", "entries": [...] }
    """
    store = get_history_store()
    entries = store.search(q) if q else store.all_entries()
    return {
        "count":   len(entries),
        "query":   q or "",
        "entries": entries,
    }


# ==============================================================
# COPILOT  (protected)
# ==============================================================

@app.post("/copilot/ask")
async def copilot_ask(
    body: dict,
    analyst: str = Depends(require_auth),
):
    """
    Ask Sentra Copilot a question about a specific security context object.

    Security contract:
      - The caller must supply a context_type ('investigation' or 'audit')
        and a context_id.
      - The backend resolves and validates the context object.
      - If the object does not exist, 404 is returned.
      - The model receives a system instruction that restricts it to
        answering only about the supplied Sentra security context.
      - Questions unrelated to the supplied context are refused by the model.
      - The backend enforces this; the frontend restriction is UX only.

    Request body:
        {
          "context_type": "investigation" | "audit",
          "context_id":   "<UUID>",
          "question":     "<analyst question>"
        }

    Returns:
        { "answer": "<Copilot response>", "context_type": "...", "context_id": "..." }
    """
    context_type = body.get("context_type", "").strip().lower()
    context_id   = body.get("context_id",   "").strip()
    question     = body.get("question",     "").strip()

    if not question:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "question is required"},
        )
    if context_type not in ("investigation", "audit", "advanced_ai_job"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "context_type must be 'investigation', 'audit' "
                    "or 'advanced_ai_job'"
                )
            },
        )
    if not context_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "context_id is required"},
        )

    # ── Resolve the context object ──
    context_obj = None

    if context_type == "investigation":
        processor = get_log_processor()
        for inv in processor.get_all_investigations():
            if inv["id"] == context_id:
                context_obj = inv
                break
        if context_obj is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"message": "Investigation not found", "context_id": context_id},
            )

    elif context_type == "audit":
        audit_data = _audits.get(context_id)
        if audit_data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"message": "Audit not found", "context_id": context_id},
            )
        context_obj = {k: v for k, v in audit_data.items() if k != "source_path"}

    elif context_type == "advanced_ai_job":
        from app.advanced_ai.orchestrator import get_job_store
        job = get_job_store().get(context_id)
        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "message": "Advanced AI job not found",
                    "context_id": context_id,
                },
            )
        context_obj = job.to_public_dict()

    # ── Build a context-specific prompt (reduced for Groq 8k TPM limit) ──
    from app.copilot_context import (
        build_copilot_context,
        build_copilot_prompt,
        enforce_token_limit,
    )

    reduced_ctx = build_copilot_context(context_type, context_obj)
    prompt = build_copilot_prompt(context_type, reduced_ctx, question)
    prompt = enforce_token_limit(prompt)  # hard safety net

    # ── Call Groq ──
    loop = asyncio.get_event_loop()

    def _sync_call():
        from app.advanced_ai.llm_provider import get_llm_provider
        provider = get_llm_provider()
        response = provider.generate(prompt, timeout=30.0)
        if not response.get("success"):
            raise RuntimeError(response.get("error", "LLM provider error"))
        return response["text"]

    try:
        answer = await loop.run_in_executor(None, _sync_call)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"message": f"Copilot AI error: {exc}"},
        )

    return {
        "answer":       answer,
        "context_type": context_type,
        "context_id":   context_id,
    }


# ==============================================================
# ADVANCED AI [BETA] — sandbox validation jobs  (protected)
# ==============================================================

app.include_router(advanced_ai_router)
