"""
Pydantic schemas for the Advanced AI [BETA] validation pipeline.

Design rules:
- internal job_id  : full UUID — never replaced or discarded
- display_id       : "AAI-XXXX" derived from first 4 hex chars of the UUID
- Every displayed pipeline step corresponds to a real backend state.
- Gemini output is ALWAYS validated through these models before use.
- Payloads are selected by Python from a fixed safe set; Gemini only
  selects strategy (payload_kind), never free-form attack strings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# ==============================================================
# ENUMS / LITERALS
# ==============================================================

JobStatus = Literal[
    "queued",
    "preparing_sandbox",
    "crawling",
    "analyzing",
    "planning_tests",
    "validating",
    "evaluating",
    "completed",
    "failed",
    "cancelled",
]

SandboxStatus = Literal[
    "creating", "ready", "running", "completed", "failed", "destroyed",
]

Verdict = Literal["VULNERABLE", "MITIGATED", "INCONCLUSIVE"]

PayloadKind = Literal["none", "benign", "sqli_error_probe", "xss_reflection_marker"]

PlanSource = Literal["gemini", "nvidia", "groq", "deterministic_fallback"]

FixStatus = Literal["pending", "fix_applied", "fix_rejected"]


# ==============================================================
# SANDBOX
# ==============================================================

class SandboxRecord(BaseModel):
    """
    An isolated validation sandbox for one authorized target.

    For the hackathon prototype the sandbox is a logical isolation
    record pointing at the locally controlled demo instance resolved
    from the trusted application registry. The base_url is NEVER
    accepted from the client.
    """

    sandbox_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = Field(..., description="app_id of the authorized target")
    target_name: str = Field(default="")
    status: SandboxStatus = Field(default="creating")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    base_url: str = Field(..., description="Internal sandbox base URL (registry-resolved)")
    source_reference: str = Field(
        default="",
        description="Where this sandbox came from, e.g. 'registry:app_meridian'",
    )


# ==============================================================
# ATTACK SURFACE (crawler output)
# ==============================================================

class DiscoveredEndpoint(BaseModel):
    """One discovered element of the sandbox attack surface."""

    endpoint: str = Field(..., description="Path such as /api/search")
    method: str = Field(default="GET")
    parameters: List[str] = Field(default_factory=list)
    authentication: str = Field(
        default="unknown",
        description="'none' | 'required' | 'unknown'",
    )
    discovered_via: str = Field(
        default="crawl",
        description="'crawl' | 'form' | 'approved_scope_verified'",
    )


# ==============================================================
# VALIDATION PLAN (Gemini output — strictly validated)
# ==============================================================

class ValidationTestSpec(BaseModel):
    """
    One controlled test inside a validation plan.

    SECURITY: payload_kind selects from a fixed allow-list of safe
    payloads owned by Python. No free-form payload ever comes from
    Gemini or from the client.
    """

    model_config = {"extra": "ignore"}

    name: str = Field(default="controlled validation test")
    method: str = Field(default="GET")
    endpoint: str = Field(..., description="Must be a discovered/approved path")
    parameter: Optional[str] = Field(default=None)
    payload_kind: PayloadKind = Field(default="none")
    baseline: bool = Field(
        default=False,
        description="True for benign baseline requests used for comparison",
    )
    kind: str = Field(
        default="generic_probe",
        description=(
            "error_based_sqli | reflected_xss | idor | auth_boundary | "
            "generic_probe"
        ),
    )


class ValidationPlan(BaseModel):
    """Structured validation strategy for one finding."""

    finding_type: str = Field(default="Unknown")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    target_endpoint: Optional[str] = Field(default=None)
    reasoning: str = Field(default="")
    tests: List[ValidationTestSpec] = Field(default_factory=list)
    source: PlanSource = Field(default="deterministic_fallback")


# ==============================================================
# EVIDENCE
# ==============================================================

class TestEvidence(BaseModel):
    """
    Evidence collected by the deterministic validator for one test.

    Secrets/tokens/cookies are redacted before storage.
    """

    test_name: str = Field(default="")
    endpoint: str = Field(..., description="Path that was requested")
    method: str = Field(default="GET")
    parameter: Optional[str] = Field(default=None)
    payload_kind: PayloadKind = Field(default="none")
    status: Optional[int] = Field(
        default=None, description="HTTP status code, None on transport failure"
    )
    response_time_ms: Optional[int] = Field(default=None)
    content_type: Optional[str] = Field(default=None)
    body_summary: str = Field(default="", description="Redacted body excerpt")
    observation: str = Field(default="", description="Deterministic observation")
    indicators: List[str] = Field(
        default_factory=list,
        description="Machine-readable indicator tags (db_error, reflection, ...)",
    )
    simulated: bool = Field(
        default=False,
        description="True when this entry is a marked demo/fallback artifact",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==============================================================
# RESULT / VERDICT
# ==============================================================

class ValidationResult(BaseModel):
    """Final classified outcome of a validation job."""

    verdict: Verdict = Field(default="INCONCLUSIVE")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(default="")
    remediation: Optional[str] = Field(default=None)
    source: PlanSource = Field(default="deterministic_fallback")


# ==============================================================
# FINDING SNAPSHOT
# ==============================================================

class FindingSnapshot(BaseModel):
    """
    The finding being validated — either an AuditFinding (code audit)
    or a SOC investigation finding, normalized to one shape.
    """

    finding_id: str = Field(default="")
    title: str = Field(default="")
    vulnerability: str = Field(default="")
    cwe: Optional[str] = Field(default=None)
    owasp: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    explanation: Optional[str] = Field(default=None)
    evidence: List[str] = Field(default_factory=list)
    file_path: Optional[str] = Field(default=None)
    line: Optional[int] = Field(default=None)
    target_endpoint: Optional[str] = Field(
        default=None,
        description=(
            "Explicit target endpoint extracted from investigation logs or "
            "audit context. Travels with the finding through the pipeline so "
            "the planner and validator always know the correct target."
        ),
    )
    origin: str = Field(default="audit", description="'audit' | 'soc'")


# ==============================================================
# JOB REQUEST
# ==============================================================

class AdvancedAIJobCreate(BaseModel):
    """
    Body of POST /advanced-ai/jobs.

    At least one Sentinel context (investigation_id or audit_id) is
    required. The target is resolved server-side from the trusted
    registry — arbitrary URLs are never accepted.

    extra='forbid' rejects any unexpected field (e.g. a client-supplied
    base_url or source_path) with HTTP 422.
    """

    model_config = {"extra": "forbid"}

    investigation_id: Optional[str] = Field(
        default=None, description="SOC investigation UUID"
    )
    audit_id: Optional[str] = Field(
        default=None, description="Completed audit UUID"
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Optional specific audit finding UUID to validate",
    )
    app_id: Optional[str] = Field(
        default=None,
        description=(
            "Authorized application identifier. Required when only an "
            "investigation_id is supplied; must match the audit's app "
            "when an audit_id is supplied."
        ),
    )


# ==============================================================
# JOB RECORD
# ==============================================================

class AdvancedAIJob(BaseModel):
    """The top-level record for one Advanced AI validation run."""

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    display_id: str = Field(default="")

    status: JobStatus = Field(default="queued")
    cancel_requested: bool = Field(default=False, exclude=True)

    # Sentinel context
    investigation_id: Optional[str] = Field(default=None)
    investigation_display_id: Optional[str] = Field(default=None)
    audit_id: Optional[str] = Field(default=None)
    audit_display_id: Optional[str] = Field(default=None)

    # Authorized target (registry-resolved, never client-supplied)
    app_id: str = Field(..., description="Registry app_id of the sandbox target")
    app_name: str = Field(default="")
    environment: str = Field(default="")

    # Finding under validation
    finding: Optional[FindingSnapshot] = Field(default=None)

    # Pipeline artifacts
    sandbox: Optional[SandboxRecord] = Field(default=None)
    attack_surface: List[DiscoveredEndpoint] = Field(default_factory=list)
    plan: Optional[ValidationPlan] = Field(default=None)
    evidence: List[TestEvidence] = Field(default_factory=list)
    result: Optional[ValidationResult] = Field(default=None)

    # Fix approval lifecycle: pending -> fix_applied | fix_rejected.
    # Only meaningful when status='completed' and result.verdict='VULNERABLE'.
    fix_status: FixStatus = Field(
        default="pending",
        description="Analyst decision on the proposed remediation.",
    )
    fix_decided_at: Optional[datetime] = Field(default=None)
    fix_decided_by: Optional[str] = Field(default=None)

    error: Optional[str] = Field(default=None)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(default=None)

    timeline: List[dict] = Field(
        default_factory=list,
        description="[{state, at}] — every real state transition",
    )

    def __init__(self, **data):
        super().__init__(**data)
        if not self.display_id:
            self.display_id = "AAI-" + self.job_id.replace("-", "")[:4]

    # ----------------------------------------------------------
    # MUTATION HELPERS
    # ----------------------------------------------------------

    def transition(self, state: JobStatus) -> None:
        """Record a state transition with timestamp."""
        self.status = state
        self.updated_at = datetime.now(timezone.utc)
        self.timeline.append({
            "state": state,
            "at": self.updated_at.isoformat(),
        })

    # ----------------------------------------------------------
    # SERIALIZATION
    # ----------------------------------------------------------

    def to_public_dict(self, include_evidence: bool = True) -> dict:
        """
        Frontend-facing representation. Internal fields
        (cancel_requested, sandbox.base_url) are excluded.
        """
        data = self.model_dump(mode="json")
        data.pop("cancel_requested", None)
        if data.get("sandbox"):
            # base_url is an internal implementation detail
            data["sandbox"].pop("base_url", None)
        if not include_evidence:
            data.pop("evidence", None)
        return data

    def to_summary_dict(self) -> dict:
        """Compact row representation for the job queue list."""
        finding = self.finding
        result = self.result
        return {
            "job_id":           self.job_id,
            "display_id":       self.display_id,
            "status":           self.status,
            "fix_status":       self.fix_status,
            "created_at":       self.created_at.isoformat(),
            "updated_at":       self.updated_at.isoformat(),
            "app_id":           self.app_id,
            "app_name":         self.app_name,
            "environment":      self.environment,
            "investigation_id": self.investigation_id,
            "investigation_display_id": self.investigation_display_id,
            "audit_id":         self.audit_id,
            "audit_display_id": self.audit_display_id,
            "finding_title":    finding.title if finding else None,
            "finding_severity": finding.severity if finding else None,
            "verdict":          result.verdict if result else None,
            "error":            self.error,
        }
