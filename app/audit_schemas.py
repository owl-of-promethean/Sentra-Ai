"""
Audit subsystem schemas for Sentra AI.

Phase 1: data structures and API contracts.
Phase 2: source-code crawler results, dependency info, knowledge queries,
         and fully-populated AuditFinding.

Design rules:
- internal_id  : full UUID — never replaced or discarded
- display_id   : "ID-XXXX" derived from first 4 hex chars of the UUID
- AuditResult.investigation_id links an audit back to its SOC investigation
- AuditFinding evidence must be traceable to crawler output or retrieved knowledge
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# ==============================================================
# DISPLAY ID HELPER
# ==============================================================

def make_display_id(uuid_str: str) -> str:
    """
    Derive a short human-friendly display ID from a UUID string.

    Examples:
        "a203f7e1-..."  ->  "ID-a203"
        "00b1cc2d-..."  ->  "ID-00b1"

    The UUID itself is NEVER replaced.  display_id is presentation-only.
    """
    # Strip hyphens so the first 4 hex chars are always from the UUID data,
    # not accidentally from a separator.
    cleaned = uuid_str.replace("-", "")
    return f"ID-{cleaned[:4]}"


# ==============================================================
# AUDIT STATUS
# ==============================================================

# Allowed values for AuditResult.status and AuditRequest responses.
AuditStatus = Literal["pending", "analyzing", "complete", "failed"]


# ==============================================================
# AUDIT REQUEST
# ==============================================================

class AuditRequest(BaseModel):
    """
    Body of POST /audit/request (Phase 3 — Authorized Application model).

    The client sends an authorized app_id instead of an arbitrary source_path.
    The backend resolves app_id to a trusted internal source location.

    source_path is intentionally removed from the public request model.
    extra="forbid" ensures any attempt to submit source_path (or any other
    unrecognised field) is rejected with HTTP 422 rather than silently ignored.
    """

    model_config = {"extra": "forbid", "json_schema_extra": {
        "example": {
            "investigation_id": "a203f7e1-4b2c-4d5e-8f9a-0b1c2d3e4f5a",
            "app_id": "app_demoshop",
            "scan_type": "quick",
            "scope_id": "application",
            "endpoint": None
        }
    }}

    investigation_id: str = Field(
        ...,
        description="Internal UUID of the SOC investigation to audit"
    )

    app_id: str = Field(
        ...,
        description="Identifier of the authorized customer application to audit"
    )

    scan_type: "AuditScanType" = Field(
        default="quick",
        description="'quick' for Quick Scan (local only) or 'deep' for Deep Scan"
    )

    scope_id: str = Field(
        default="application",
        description=(
            "'application' to scan the entire app, "
            "'endpoint' to scan a specific permitted path"
        )
    )

    endpoint: Optional[str] = Field(
        default=None,
        description=(
            "Required when scope_id='endpoint'. "
            "Must be one of the application's allowed_scopes paths. "
            "Arbitrary filesystem paths and URLs are rejected."
        )
    )


# ==============================================================
# CODE LOCATION  (sparse for Phase 1 — populated in Phase 2+)
# ==============================================================

class CodeLocation(BaseModel):
    """
    Points to a specific region in a source file.

    All fields are optional in Phase 1 because no source is analysed yet.
    Phase 2+ will populate them from the code extraction step.
    """

    file_path: Optional[str] = Field(
        default=None,
        description="Relative path to the affected source file"
    )

    start_line: Optional[int] = Field(
        default=None,
        description="First line of the relevant code block (1-based)"
    )

    end_line: Optional[int] = Field(
        default=None,
        description="Last line of the relevant code block (1-based)"
    )

    snippet: Optional[str] = Field(
        default=None,
        description="The actual source-code block extracted from the file"
    )

    language: Optional[str] = Field(
        default=None,
        description="Programming language of the source file"
    )


# ==============================================================
# AUDIT FINDING  (Phase 2: fully populated)
# ==============================================================

class AuditFinding(BaseModel):
    """
    A single code-level security finding produced during an audit.

    Phase 1: structure is defined but findings list is empty.
    Phase 2: Gemini populates all fields based on crawler evidence.

    Critical rule: vulnerability classification must come from evidence
    observed in source code, NOT from CVE/CWE documents alone.
    CVE/CWE documents are reference material, not proof of vulnerability.
    """

    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique ID for this individual finding"
    )

    title: Optional[str] = Field(
        default=None,
        description="Short human-readable title (e.g. 'SQL Injection in login handler')"
    )

    vulnerability: Optional[str] = Field(
        default=None,
        description="Vulnerability category label (e.g. 'SQL Injection')"
    )

    cwe: Optional[str] = Field(
        default=None,
        description="CWE identifier (e.g. 'CWE-89')"
    )

    owasp: Optional[str] = Field(
        default=None,
        description="OWASP category (e.g. 'A03:2021 Injection')"
    )

    severity: Optional[str] = Field(
        default=None,
        description="Severity: LOW / MEDIUM / HIGH / CRITICAL"
    )

    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="AI confidence in the finding (0.0 = uncertain, 1.0 = certain)"
    )

    explanation: Optional[str] = Field(
        default=None,
        description="Why this code is potentially vulnerable, grounded in observed source evidence"
    )

    evidence: List[str] = Field(
        default_factory=list,
        description=(
            "Specific observations from the source code that support this finding. "
            "Each item must be traceable to the crawler output — never invented."
        )
    )

    location: Optional[CodeLocation] = Field(
        default=None,
        description="Exact source location of the finding"
    )

    remediation: Optional[str] = Field(
        default=None,
        description="Suggested safe fix for this finding"
    )

    references: List[str] = Field(
        default_factory=list,
        description=(
            "Supporting references from retrieved knowledge (CWE pages, OWASP links, etc.). "
            "These are reference material, not additional evidence."
        )
    )


# ==============================================================
# DEPENDENCY INFO  (Phase 2C)
# ==============================================================

class DependencyInfo(BaseModel):
    """
    A single dependency/package discovered from a project manifest.

    name and version come directly from the manifest file.
    manager identifies the package ecosystem.
    source_file is the manifest where this was found.

    Design rule: presence of a dependency is NOT evidence of vulnerability.
    This data is used only to retrieve relevant security reference knowledge.
    """

    name: str = Field(..., description="Package/library name")
    version: Optional[str] = Field(
        default=None,
        description="Version string as declared in the manifest (may be a range)"
    )
    manager: str = Field(
        ...,
        description="Package manager / ecosystem (e.g. 'pip', 'npm', 'composer')"
    )
    source_file: str = Field(
        ...,
        description="Relative path of the manifest file this came from"
    )


# ==============================================================
# AUDIT KNOWLEDGE QUERY  (Phase 2D)
# ==============================================================

class AuditKnowledgeQuery(BaseModel):
    """
    Structured query passed to the audit knowledge retriever.

    Provides the retriever with enough context to find relevant
    security reference material WITHOUT making vulnerability claims.

    The retriever must treat all returned documents as reference
    material, never as proof of vulnerability.
    """

    technologies: List[str] = Field(
        default_factory=list,
        description="Detected technologies (e.g. ['python', 'flask', 'sqlite'])"
    )

    packages: List[DependencyInfo] = Field(
        default_factory=list,
        description="Detected dependencies from project manifests"
    )

    cwe_hints: List[str] = Field(
        default_factory=list,
        description=(
            "CWE identifiers that may be relevant given the detected stack "
            "(e.g. ['CWE-89', 'CWE-79']). These are search hints, not findings."
        )
    )

    owasp_hints: List[str] = Field(
        default_factory=list,
        description=(
            "OWASP categories that may be relevant "
            "(e.g. ['A03:2021 Injection', 'A07:2021 Authentication'])"
        )
    )

    trigger_context: List[str] = Field(
        default_factory=list,
        description=(
            "SOC trigger reasons from the associated investigation. "
            "Used to narrow knowledge retrieval to relevant attack patterns."
        )
    )


# ==============================================================
# AUDIT SCAN TYPE
# ==============================================================

AuditScanType = Literal["quick", "deep"]


# ==============================================================
# AUDIT RESULT
# ==============================================================

class AuditResult(BaseModel):
    """
    The top-level record for one code audit run.

    Links back to the originating SOC investigation via investigation_id.
    display_id is derived from audit_id for UI presentation.

    Phase 1: status stays 'pending', findings list is empty.
    Phase 2+ will update status and populate findings.
    Phase 3: adds app identity fields (app_id, app_name, app_website, environment).
    """

    audit_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Internal UUID for this audit run"
    )

    display_id: str = Field(
        default="",
        description="Human-friendly audit reference, e.g. 'AUDIT-a203'"
    )

    investigation_id: str = Field(
        ...,
        description="Internal UUID of the linked SOC investigation"
    )

    investigation_display_id: str = Field(
        default="",
        description="display_id of the linked SOC investigation, for UI cross-linking"
    )

    # Authorized application identity (Phase 3)
    app_id: Optional[str] = Field(
        default=None,
        description="Authorized application identifier"
    )

    app_name: Optional[str] = Field(
        default=None,
        description="Human-readable application name"
    )

    app_website: Optional[str] = Field(
        default=None,
        description="Application website URL (frontend display only)"
    )

    environment: Optional[str] = Field(
        default=None,
        description="Deployment environment (e.g. 'staging', 'sandbox')"
    )

    scope_id: Optional[str] = Field(
        default=None,
        description="Scope used for this audit ('application' or 'endpoint')"
    )

    scope_endpoint: Optional[str] = Field(
        default=None,
        description="Specific endpoint audited (when scope_id='endpoint')"
    )

    scan_type: AuditScanType = Field(
        default="quick",
        description="Scan type: 'quick' (local only) or 'deep' (with online intelligence)"
    )

    # Internal — NOT serialized in normal frontend responses.
    # The audit engine reads this; the API omits it from public endpoints.
    source_path: Optional[str] = Field(
        default=None,
        description="Internal filesystem path used by the audit engine (not forwarded to client)"
    )

    status: AuditStatus = Field(
        default="pending",
        description="Current audit status: pending / analyzing / complete / failed"
    )

    files_scanned: int = Field(
        default=0,
        description="Number of source files discovered and read"
    )

    technologies: List[str] = Field(
        default_factory=list,
        description="Detected technologies/languages in the scanned project"
    )

    dependencies: List[DependencyInfo] = Field(
        default_factory=list,
        description="Detected package dependencies from project manifests"
    )

    findings: List[AuditFinding] = Field(
        default_factory=list,
        description="Code-level security findings from Gemini analysis"
    )

    error: Optional[str] = Field(
        default=None,
        description="Error message if status='failed'"
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this audit was requested"
    )

    completed_at: Optional[datetime] = Field(
        default=None,
        description="When this audit completed (None while pending/analyzing)"
    )

    def __init__(self, **data):
        super().__init__(**data)
        # Derive display IDs from the underlying UUIDs if not explicitly set.
        if not self.display_id:
            self.display_id = "AUDIT-" + self.audit_id.replace("-", "")[:4]
        if not self.investigation_display_id and self.investigation_id:
            self.investigation_display_id = make_display_id(self.investigation_id)


# ==============================================================
# HISTORY ENTRY
# ==============================================================

class HistoryEntry(BaseModel):
    """
    A lightweight record stored in the local history log.

    Covers both SOC investigations and audit runs in one unified list.
    The frontend can filter by entry_type to show separate tabs.
    """

    entry_type: Literal["soc", "audit", "advanced_ai"] = Field(
        ...,
        description=(
            "'soc' for an investigation, 'audit' for a code audit, "
            "'advanced_ai' for an Advanced AI [BETA] validation job"
        )
    )

    internal_id: str = Field(
        ...,
        description="Full UUID of the investigation or audit"
    )

    display_id: str = Field(
        ...,
        description="Human-friendly reference, e.g. 'ID-a203' or 'AUDIT-a203'"
    )

    # SOC-specific (populated for entry_type='soc')
    activity_type: Optional[str] = Field(
        default=None,
        description="Activity label from the SOC finding (once analyzed)"
    )

    trigger_reasons: Optional[List[str]] = Field(
        default=None,
        description="Raw trigger reasons that created the investigation"
    )

    # Shared fields
    severity: Optional[str] = Field(
        default=None,
        description="Severity level: LOW / MEDIUM / HIGH / CRITICAL"
    )

    status: str = Field(
        ...,
        description="Current status of the item"
    )

    summary: Optional[str] = Field(
        default=None,
        description="Short human-readable summary"
    )

    timestamp: datetime = Field(
        ...,
        description="When this entry was created (used for chronological ordering)"
    )

    # Audit-specific (populated for entry_type='audit')
    investigation_id: Optional[str] = Field(
        default=None,
        description="For audits: the linked SOC investigation UUID"
    )

    investigation_display_id: Optional[str] = Field(
        default=None,
        description="For audits: the linked SOC investigation display_id"
    )
