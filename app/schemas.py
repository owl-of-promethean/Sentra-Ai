"""
Pydantic schemas for Sentra AI data models.

These schemas define the structure of security findings and other data entities.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone


class SecurityFinding(BaseModel):
    """
    Structured security finding produced by the Gemini analysis layer.

    Python prepares evidence; Gemini reasons about what it means.
    Fields deliberately avoid forcing an attack conclusion — the AI
    must weigh alternatives and express uncertainty where appropriate.
    """

    severity: str = Field(
        ...,
        description="Severity level: LOW / MEDIUM / HIGH / CRITICAL",
        examples=["HIGH", "CRITICAL"]
    )

    activity_type: str = Field(
        ...,
        description=(
            "Observed activity category as assessed by the AI "
            "(e.g., 'Possible credential attack', 'Anomalous traffic pattern'). "
            "Must not be a hard-coded label — the AI must justify this."
        )
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="AI confidence in the finding from 0.0 (uncertain) to 1.0 (certain)"
    )

    summary: str = Field(
        ...,
        description="Concise human-readable summary of the finding"
    )

    evidence: List[str] = Field(
        default_factory=list,
        description="Specific observations from the logs that support this finding"
    )

    possible_explanations: List[str] = Field(
        default_factory=list,
        description=(
            "Alternative explanations the AI considered, including legitimate ones. "
            "Captures the AI's reasoning process."
        )
    )

    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Analyst actions recommended based on the observed evidence"
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this finding was generated"
    )

    investigation_id: Optional[str] = Field(
        default=None,
        description="ID of the investigation that produced this finding"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "severity": "MEDIUM",
                "activity_type": "Possible authentication attack or misconfigured client",
                "confidence": 0.65,
                "summary": (
                    "Multiple authentication failures from a single source IP "
                    "in a 10-second window. Warrants investigation."
                ),
                "evidence": [
                    "7 HTTP 401 responses from 10.10.10.50 in 10 seconds",
                    "All failures targeted /api/login",
                    "Single user-agent across all requests"
                ],
                "possible_explanations": [
                    "Brute-force or credential-stuffing attack",
                    "Misconfigured application or service account",
                    "Expired credentials triggering automated retry",
                    "Legitimate user locked out after password change"
                ],
                "recommended_actions": [
                    "Review authentication logs for 10.10.10.50",
                    "Check whether the source IP belongs to a known service account",
                    "Consider temporary rate-limiting if pattern continues",
                    "Do not block without confirming the source is not internal"
                ]
            }
        }


class LogEntry(BaseModel):
    """
    Represents a single security log entry.
    
    This is the basic unit of data received from the vulnerable application.
    """

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the event occurred"
    )

    event_type: str = Field(
        ...,
        description="Type of security event"
    )

    source_ip: Optional[str] = Field(
        default=None,
        description="IP address where the request originated"
    )

    target_endpoint: Optional[str] = Field(
        default=None,
        description="Target endpoint or resource"
    )

    details: dict = Field(
        default_factory=dict,
        description="Additional context and metadata about the event"
    )

    user_agent: Optional[str] = Field(
        default=None,
        description="User agent string from the request"
    )


class InvestigationWindow(BaseModel):
    """
    Represents a group of related logs that form an investigation window.
    
    Python creates these windows when it detects suspicious activity patterns.
    """

    id: str = Field(
        description="Unique identifier for this investigation window"
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this window was created"
    )

    trigger_reason: str = Field(
        ...,
        description="Why this investigation was triggered"
    )

    logs: List[LogEntry] = Field(
        default_factory=list,
        description="All log entries included in this window"
    )

    status: str = Field(
        default="pending",
        description="Status: pending, analyzing, complete"
    )
