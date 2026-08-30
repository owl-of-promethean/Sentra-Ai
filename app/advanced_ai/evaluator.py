"""
Deterministic evidence evaluation for Advanced AI [BETA].

The validator collects evidence; Gemini is the preferred interpreter
(see gemini_bridge.evaluate_evidence_via_gemini). This module is the
safe, offline fallback used when Gemini is unavailable, times out, or
returns malformed output.

Classification rule: NEVER declare something vulnerable merely because
an attack string was sent. A verdict requires observable behavioral
difference between the controlled probe and its benign baseline.
"""

from __future__ import annotations

from typing import List

from app.advanced_ai.schemas import TestEvidence, ValidationResult, ValidationPlan


def evaluate_fallback(
    plan: ValidationPlan,
    evidence: List[TestEvidence],
) -> ValidationResult:
    """
    Deterministically classify collected evidence.

    Returns a ValidationResult with source='deterministic_fallback'.
    """
    real = [e for e in evidence if not e.simulated]

    if not real:
        return ValidationResult(
            verdict="INCONCLUSIVE",
            confidence=0.1,
            reasoning=(
                "No usable evidence was collected (all requests failed or "
                "were skipped). No conclusion can be drawn."
            ),
            remediation=None,
            source="deterministic_fallback",
        )

    baselines = [e for e in real if _is_baseline(e, plan)]
    probes = [e for e in real if not _is_baseline(e, plan)]

    # ---- SQL injection (error-based) ---------------------------------
    if plan.finding_type == "SQL Injection" or any(
        t.kind == "error_based_sqli" for t in plan.tests
    ):
        probe_err = [e for e in probes if "db_error_signature" in e.indicators]
        base_err = [e for e in baselines if "db_error_signature" in e.indicators]

        if probe_err and not base_err:
            return ValidationResult(
                verdict="VULNERABLE",
                confidence=0.9,
                reasoning=(
                    "The single-quote error probe produced a database error "
                    "signature while the benign baseline did not. This "
                    "behavioral difference indicates user input is being "
                    "interpolated into SQL without sanitization."
                ),
                remediation=(
                    "Use parameterized queries / prepared statements for "
                    "all database access. Never concatenate user input "
                    "into SQL. Suppress raw database errors in responses."
                ),
                source="deterministic_fallback",
            )

        if probe_err and base_err:
            return ValidationResult(
                verdict="INCONCLUSIVE",
                confidence=0.4,
                reasoning=(
                    "Both the probe and the baseline returned database "
                    "error signatures, so the difference in behavior is "
                    "not attributable to the controlled input."
                ),
                source="deterministic_fallback",
            )

        rejected = [e for e in probes if e.status in (400, 422)]
        if rejected and baselines and all(
            b.status in (200,) for b in baselines
        ):
            return ValidationResult(
                verdict="MITIGATED",
                confidence=0.7,
                reasoning=(
                    "The application rejected the malformed input with an "
                    "input-validation error while accepting the benign "
                    "baseline, indicating defensive input handling."
                ),
                source="deterministic_fallback",
            )

        return ValidationResult(
            verdict="INCONCLUSIVE",
            confidence=0.4,
            reasoning=(
                "The probe did not produce an observable database error "
                "difference. The endpoint may be safe, or the "
                "vulnerability may be blind — this minimal probe cannot "
                "distinguish the two without further testing."
            ),
            source="deterministic_fallback",
        )

    # ---- XSS (reflection) --------------------------------------------
    if plan.finding_type == "XSS" or any(
        t.kind == "reflected_xss" for t in plan.tests
    ):
        reflected = [e for e in probes if "unescaped_reflection" in e.indicators]
        if reflected:
            return ValidationResult(
                verdict="VULNERABLE",
                confidence=0.85,
                reasoning=(
                    "A benign marker was reflected back into the response "
                    "without encoding, indicating user input reaches the "
                    "output unescaped (a precondition for reflected XSS)."
                ),
                remediation=(
                    "Contextually encode all user input on output, apply a "
                    "strict Content-Security-Policy, and validate input."
                ),
                source="deterministic_fallback",
            )
        return ValidationResult(
            verdict="MITIGATED" if probes else "INCONCLUSIVE",
            confidence=0.6 if probes else 0.2,
            reasoning=(
                "The marker was not reflected unescaped; output appears "
                "encoded or the input was not echoed."
            ),
            source="deterministic_fallback",
        )

    # ---- IDOR / access control ----------------------------------------
    if plan.finding_type in ("IDOR", "Broken Access Control") or any(
        t.kind == "idor" for t in plan.tests
    ):
        open_access = [
            e for e in probes if "data_returned_unauthenticated" in e.indicators
        ]
        enforced = [e for e in real if "auth_enforced" in e.indicators]

        if open_access:
            return ValidationResult(
                verdict="VULNERABLE",
                confidence=0.8,
                reasoning=(
                    "Object data was returned without any credentials, "
                    "demonstrating a missing authorization boundary."
                ),
                remediation=(
                    "Enforce server-side ownership/role checks for every "
                    "object reference. Deny by default."
                ),
                source="deterministic_fallback",
            )
        if enforced:
            return ValidationResult(
                verdict="INCONCLUSIVE",
                confidence=0.5,
                reasoning=(
                    "The sandbox enforced authentication; Sentinel holds no "
                    "authorized credentials, so cross-user authorization "
                    "behavior could not be observed."
                ),
                source="deterministic_fallback",
            )

    # ---- Missing authentication / info exposure -----------------------
    if plan.finding_type in ("Missing Authentication",
                             "Sensitive Information Exposure") or any(
        t.kind == "auth_boundary" for t in plan.tests
    ):
        open_access = [
            e for e in real if "data_returned_unauthenticated" in e.indicators
        ]
        sensitive = [e for e in real if "sensitive_content" in e.indicators]
        if open_access or sensitive:
            return ValidationResult(
                verdict="VULNERABLE",
                confidence=0.75,
                reasoning=(
                    "A request without credentials returned application "
                    "content"
                    + (" including apparently sensitive fields" if sensitive else "")
                    + ", indicating a missing or weak authentication boundary."
                ),
                remediation=(
                    "Require authentication for this endpoint and remove "
                    "sensitive data from responses."
                ),
                source="deterministic_fallback",
            )
        enforced = [e for e in real if "auth_enforced" in e.indicators]
        if enforced:
            return ValidationResult(
                verdict="MITIGATED",
                confidence=0.7,
                reasoning="The endpoint enforced authentication (401/403).",
                source="deterministic_fallback",
            )

    # ---- Default -------------------------------------------------------
    return ValidationResult(
        verdict="INCONCLUSIVE",
        confidence=0.3,
        reasoning=(
            "The collected evidence does not contain a deterministic "
            "signal strong enough to classify the finding. No exploitable "
            "behavior was observed, but absence of signal is not proof "
            "of safety."
        ),
        source="deterministic_fallback",
    )


def _is_baseline(evidence: TestEvidence, plan: ValidationPlan) -> bool:
    """Match evidence back to its plan test to detect baseline tests."""
    for test in plan.tests:
        if test.name == evidence.test_name:
            return test.baseline
    return evidence.payload_kind == "benign"
