"""
FastAPI routes for Advanced AI [BETA] validation jobs.

Security contract (enforced entirely on the backend):
  - Every job requires at least one real Sentra context
    (investigation_id and/or audit_id).
  - The target application must exist in the trusted registry, be
    active, AND be explicitly approved for Advanced AI.
  - When an audit_id is supplied, its stored app_id must match the
    requested target — mismatched combinations are rejected.
  - finding_id must belong to the referenced audit.
  - The sandbox base_url is resolved server-side from the registry;
    client-supplied URLs/paths are never accepted (extra='forbid').

A failed Advanced AI job never modifies or deletes the underlying
audit or investigation records.
"""

from __future__ import annotations

import asyncio
import os
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.advanced_ai.events import log_event
from app.advanced_ai.orchestrator import (
    JobContext,
    Orchestrator,
    get_job_store,
)
from app.advanced_ai.schemas import (
    AdvancedAIJob,
    AdvancedAIJobCreate,
    FindingSnapshot,
)
from app.auth import require_auth
from app.authorized_apps import get_advanced_ai_target
from datetime import datetime, timezone

router = APIRouter(prefix="/advanced-ai", tags=["Advanced AI [BETA]"])


# ==============================================================
# MODULE STATE
# ==============================================================

# JobContext per running job (holds the trusted AuthorizedApp object).
_job_contexts: Dict[str, JobContext] = {}

# Shared orchestrator with real HTTP collaborators.
_orchestrator = Orchestrator()

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _use_gemini() -> bool:
    """Allow offline demo runs via ADVANCED_AI_USE_GEMINI=false."""
    return os.getenv("ADVANCED_AI_USE_GEMINI", "true").strip().lower() != "false"


# ==============================================================
# FINDING SNAPSHOT BUILDERS
# ==============================================================

def _snapshot_from_audit_finding(f: dict) -> FindingSnapshot:
    """Build a FindingSnapshot from a stored AuditFinding dict."""
    loc = f.get("location") or {}
    target_endpoint = None
    evidence = list(f.get("evidence") or [])
    for ev in evidence:
        if isinstance(ev, str) and ev.startswith("/"):
            target_endpoint = ev.split("?")[0]
            break
    return FindingSnapshot(
        finding_id=f.get("finding_id", ""),
        title=f.get("title") or f.get("vulnerability") or "Unknown finding",
        vulnerability=f.get("vulnerability") or f.get("title") or "",
        cwe=f.get("cwe"),
        owasp=f.get("owasp"),
        severity=f.get("severity"),
        confidence=f.get("confidence"),
        explanation=f.get("explanation"),
        evidence=evidence,
        file_path=loc.get("file_path"),
        line=loc.get("start_line"),
        target_endpoint=target_endpoint,
        origin="audit",
    )


def _snapshot_from_soc_finding(investigation: dict) -> Optional[FindingSnapshot]:
    """Build a FindingSnapshot from a SOC investigation finding.

    When the finding is a real Gemini analysis result, all fields are
    extracted.  When only trigger reasons are available (Gemini hasn't
    finished yet), a minimal snapshot is built from the trigger signals
    so a job can still run.

    Target endpoint and evidence are enriched from investigation logs
    when the finding itself doesn't contain them.
    """
    finding = investigation.get("finding")
    target_endpoint = _extract_target_endpoint(investigation)
    if not isinstance(finding, dict) or "error" in finding:
        # Fall back to raw trigger reasons so a job can still run.
        reasons = investigation.get("trigger_reasons") or []
        if not reasons:
            return None
        # Preserve activity_type from finding dict if available
        # (often populated even when the rest of the analysis failed).
        activity_type = None
        if isinstance(finding, dict):
            activity_type = finding.get("activity_type")
        evidence_list = list(reasons)
        if target_endpoint:
            evidence_list.append(f"Target endpoint from logs: {target_endpoint}")
        title = activity_type or ", ".join(reasons[:3])
        return FindingSnapshot(
            finding_id=investigation.get("id", ""),
            title=title,
            vulnerability=activity_type or ", ".join(reasons[:3]),
            explanation="Derived from SOC trigger signals.",
            evidence=evidence_list,
            target_endpoint=target_endpoint,
            origin="soc",
        )
    # Real Gemini finding available
    evidence_list = list(finding.get("evidence") or [])
    if target_endpoint and not any("endpoint" in e.lower() or "path" in e.lower() for e in evidence_list):
        evidence_list.append(f"Target endpoint from logs: {target_endpoint}")
    return FindingSnapshot(
        finding_id=investigation.get("id", ""),
        title=finding.get("activity_type", "Suspicious activity"),
        vulnerability=finding.get("activity_type", ""),
        severity=finding.get("severity"),
        confidence=finding.get("confidence"),
        explanation=finding.get("summary"),
        evidence=evidence_list,
        target_endpoint=target_endpoint,
        origin="soc",
    )


def _extract_target_endpoint(investigation: dict) -> Optional[str]:
    """Extract the most common target path from investigation logs."""
    logs = investigation.get("logs", [])
    if not logs:
        return None
    from collections import Counter
    paths = Counter()
    for log in logs:
        path = log.get("path", "")
        if path:
            # Normalize: strip query string for counting
            clean_path = path.split("?")[0] if "?" in path else path
            paths[clean_path] += 1
    if paths:
        most_common = paths.most_common(1)[0][0]
        return most_common
    return None


# ==============================================================
# RESOLUTION / AUTHORIZATION HELPERS
# ==============================================================

def _get_audit_store() -> dict:
    """Lazy import avoids a circular import with app.main."""
    from app.main import _audits
    return _audits


def _find_investigation(investigation_id: str) -> Optional[dict]:
    from app.log_processor import get_log_processor
    for inv in get_log_processor().get_all_investigations():
        if inv["id"] == investigation_id:
            return inv
    return None


def _pick_top_audit_finding(audit_data: dict) -> Optional[dict]:
    findings = audit_data.get("findings") or []
    actionable = [
        f for f in findings
        if (f.get("severity") or "").upper() != "SAFE"
    ]
    if not actionable:
        return None
    actionable.sort(
        key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "").upper(), 0),
        reverse=True,
    )
    return actionable[0]


# ==============================================================
# BACKGROUND RUNNER
# ==============================================================

async def _run_advanced_ai_job(job_id: str) -> None:
    """Run one job through the orchestrator without blocking the loop."""
    store = get_job_store()
    job = store.get(job_id)
    ctx = _job_contexts.get(job_id)
    if job is None or ctx is None:
        print(f"  [AdvancedAI] WARNING: job {job_id} missing store/context")
        return

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _orchestrator.run, job, ctx)
    except Exception as exc:
        # The orchestrator never raises, but be defensive anyway.
        job.error = f"Executor error: {exc}"
        job.transition("failed")
        store.add(job)
        log_event("advanced_ai_failed", job_id=job_id, error=str(exc))


# ==============================================================
# ENDPOINTS
# ==============================================================

@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
async def create_job(
    body: AdvancedAIJobCreate,
    analyst: str = Depends(require_auth),
):
    """
    Create an Advanced AI validation job.

    Requires at least one Sentra context (investigation_id or
    audit_id). The target is resolved from the trusted registry.
    """
    # ---- 1. At least one valid Sentra context --------------------
    if not body.investigation_id and not body.audit_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "At least one Sentra context is required: "
                    "provide investigation_id and/or audit_id."
                )
            },
        )

    audits = _get_audit_store()

    # ---- 2. Resolve the audit (if provided) ------------------------
    audit_data = None
    if body.audit_id:
        audit_data = audits.get(body.audit_id)
        if audit_data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"message": "Audit not found", "audit_id": body.audit_id},
            )

    # ---- 3. Resolve the investigation (if provided) ----------------
    investigation = None
    if body.investigation_id:
        investigation = _find_investigation(body.investigation_id)
        if investigation is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "message": "Investigation not found",
                    "investigation_id": body.investigation_id,
                },
            )

    # ---- 4. Resolve + authorize the target application -------------
    if audit_data is not None:
        target_app_id = audit_data.get("app_id")
        if body.app_id and body.app_id != target_app_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": (
                        "Target mismatch: the audit belongs to "
                        f"'{target_app_id}', not '{body.app_id}'."
                    )
                },
            )
    else:
        target_app_id = body.app_id

    if not target_app_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "app_id is required when no audit_id is supplied."
                )
            },
        )

    app = get_advanced_ai_target(target_app_id)
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": (
                    f"Application '{target_app_id}' is not an authorized "
                    "Advanced AI target. Only registered applications "
                    "explicitly approved for Advanced AI may be validated."
                ),
                "app_id": target_app_id,
            },
        )

    # ---- 5. Cross-check: audit must belong to the target -----------
    if audit_data is not None and audit_data.get("app_id") != app.app_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": (
                    "The audit does not belong to the requested target "
                    "application."
                )
            },
        )

    # Investigation ↔ audit consistency
    if audit_data is not None and investigation is not None:
        if audit_data.get("investigation_id") != investigation["id"]:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": (
                        "The investigation does not belong to the "
                        "referenced audit."
                    )
                },
            )
    # Default the investigation from the audit when not given
    if investigation is None and audit_data is not None:
        linked = audit_data.get("investigation_id")
        if linked:
            investigation = _find_investigation(linked)

    # ---- 6. Select the finding to validate --------------------------
    finding: Optional[FindingSnapshot] = None

    if body.finding_id:
        # Explicit finding_id always takes highest priority.
        if audit_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "finding_id requires an audit_id context."
                },
            )
        match = next(
            (f for f in (audit_data.get("findings") or [])
             if f.get("finding_id") == body.finding_id),
            None,
        )
        if match is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "message": "Finding not found in this audit",
                    "finding_id": body.finding_id,
                },
            )
        finding = _snapshot_from_audit_finding(match)
    elif investigation is not None:
        # The investigation's Gemini finding (status="analyzed") is
        # authoritative — it describes the actual observed attack.
        # When the investigation hasn't been analyzed yet (pending,
        # triggered, analysis_failed) the SOC snapshot falls back to
        # generic trigger_reasons ("multiple failures from ...").
        # In that case, prefer the audit's code-level finding when
        # one is available.
        inv_analyzed = investigation.get("status") == "analyzed"
        if inv_analyzed:
            finding = _snapshot_from_soc_finding(investigation)
        elif audit_data is not None:
            top = _pick_top_audit_finding(audit_data)
            if top is not None:
                finding = _snapshot_from_audit_finding(top)
        if finding is None:
            # Last resort: SOC trigger-reasons snapshot, or fall
            # through to the 422 error below.
            finding = _snapshot_from_soc_finding(investigation)
    elif audit_data is not None:
        top = _pick_top_audit_finding(audit_data)
        if top is not None:
            finding = _snapshot_from_audit_finding(top)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": (
                    "No validatable finding available. The audit has no "
                    "actionable findings and the investigation has no "
                    "analysis result."
                )
            },
        )

    # ---- 7. Create the job ------------------------------------------
    from app.audit_schemas import make_display_id

    job = AdvancedAIJob(
        investigation_id=investigation["id"] if investigation else None,
        investigation_display_id=(
            make_display_id(investigation["id"]) if investigation else None
        ),
        audit_id=audit_data.get("audit_id") if audit_data else None,
        audit_display_id=audit_data.get("display_id", "") if audit_data else None,
        app_id=app.app_id,
        app_name=app.name,
        environment=app.environment,
        finding=finding,
    )
    job.transition("queued")

    store = get_job_store()
    store.add(job)
    _job_contexts[job.job_id] = JobContext(
        app=app,
        finding=finding,
        investigation=investigation,
        use_gemini=_use_gemini(),
    )

    # History entry (best effort)
    try:
        from app.history import get_history_store
        get_history_store().add_advanced_ai_entry(job)
    except Exception as exc:
        print(f"  [History] Failed to add Advanced AI entry: {exc}")

    log_event(
        "advanced_ai_job_created",
        job_id=job.job_id,
        app_id=app.app_id,
        audit_id=job.audit_id,
        investigation_id=job.investigation_id,
        finding=finding.title,
        analyst=analyst,
    )

    # ---- 8. Launch ----------------------------------------------------
    asyncio.create_task(_run_advanced_ai_job(job.job_id))

    return {
        "job_id": job.job_id,
        "display_id": job.display_id,
        "status": job.status,
        "app_id": job.app_id,
        "app_name": job.app_name,
        "finding": finding.title,
        "message": (
            f"Validation job queued for '{app.name}'. "
            "Poll GET /advanced-ai/jobs/{job_id} for live status."
        ),
    }


@router.get("/jobs")
async def list_jobs(analyst: str = Depends(require_auth)):
    """List all Advanced AI jobs, newest first (queue summaries)."""
    jobs = get_job_store().list()
    return {
        "count": len(jobs),
        "jobs": [j.to_summary_dict() for j in jobs],
    }


@router.get("/metrics")
async def job_metrics(analyst: str = Depends(require_auth)):
    """Real Advanced AI metrics — never fabricated statistics."""
    return get_job_store().metrics()


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, analyst: str = Depends(require_auth)):
    """Full job detail for frontend polling."""
    job = get_job_store().get(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Job not found", "job_id": job_id},
        )
    return job.to_public_dict()


@router.get("/jobs/{job_id}/evidence")
async def get_job_evidence(job_id: str, analyst: str = Depends(require_auth)):
    """Evidence collected during validation."""
    job = get_job_store().get(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Job not found", "job_id": job_id},
        )
    return {
        "job_id": job.job_id,
        "display_id": job.display_id,
        "status": job.status,
        "evidence": [e.model_dump(mode="json") for e in job.evidence],
        "result": (
            job.result.model_dump(mode="json") if job.result else None
        ),
    }


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, analyst: str = Depends(require_auth)):
    """
    Request cancellation of a running job.

    The orchestrator checks the flag between pipeline phases and
    performs sandbox cleanup. Terminal jobs cannot be cancelled.
    """
    job = get_job_store().get(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Job not found", "job_id": job_id},
        )

    if job.status in ("completed", "failed", "cancelled"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Job is already {job.status}.",
                "job_id": job_id,
            },
        )

    job.cancel_requested = True
    log_event("advanced_ai_cancel_requested", job_id=job_id, analyst=analyst)
    return {
        "job_id": job_id,
        "status": job.status,
        "message": "Cancellation requested. The job will stop at the next phase boundary.",
    }


# ==============================================================
# FIX APPROVAL / REJECTION  (sandbox-scoped only)
# ==============================================================

def _require_completed_job(job_id: str):
    """Return a completed job or raise the appropriate HTTPException."""
    job = get_job_store().get(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Job not found", "job_id": job_id},
        )
    if job.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": (
                    f"Job is {job.status}. Fix approval/rejection is only "
                    "available for completed jobs."
                ),
                "job_id": job_id,
            },
        )
    return job


@router.post("/jobs/{job_id}/approve")
async def approve_fix(job_id: str, analyst: str = Depends(require_auth)):
    """
    Approve the proposed remediation fix for a completed job.

    The fix is recorded as approved against the sandbox copy only.
    The original vulnerable application is NEVER modified.
    """
    job = _require_completed_job(job_id)

    if job.fix_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Fix decision already recorded: {job.fix_status}.",
                "job_id": job_id,
            },
        )

    job.fix_status = "fix_applied"
    job.fix_decided_at = datetime.now(timezone.utc)
    job.fix_decided_by = analyst
    job.updated_at = job.fix_decided_at
    get_job_store().add(job)

    log_event(
        "advanced_ai_fix_approved",
        job_id=job_id,
        analyst=analyst,
        verdict=job.result.verdict if job.result else None,
    )

    return {
        "job_id": job_id,
        "display_id": job.display_id,
        "fix_status": job.fix_status,
        "message": (
            "Fix accepted for the sandbox environment. "
            "The original application remains unchanged."
        ),
    }


@router.post("/jobs/{job_id}/reject")
async def reject_fix(job_id: str, analyst: str = Depends(require_auth)):
    """
    Reject the proposed remediation fix for a completed job.

    The sandbox code is left unchanged; the rejection is recorded
    so the job queue reflects the analyst's decision.
    """
    job = _require_completed_job(job_id)

    if job.fix_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Fix decision already recorded: {job.fix_status}.",
                "job_id": job_id,
            },
        )

    job.fix_status = "fix_rejected"
    job.fix_decided_at = datetime.now(timezone.utc)
    job.fix_decided_by = analyst
    job.updated_at = job.fix_decided_at
    get_job_store().add(job)

    log_event(
        "advanced_ai_fix_rejected",
        job_id=job_id,
        analyst=analyst,
        verdict=job.result.verdict if job.result else None,
    )

    return {
        "job_id": job_id,
        "display_id": job.display_id,
        "fix_status": job.fix_status,
        "message": "Fix rejected. Sandbox code left unchanged.",
    }
