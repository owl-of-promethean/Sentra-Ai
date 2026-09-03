"""
Attack planner for Advanced AI [BETA] — deterministic layer.

Maps a finding to the appropriate controlled validation strategy.
This module is the SAFE FALLBACK planner: it always produces a
constrained, non-destructive plan and never needs Gemini. Gemini's
structured plan (see gemini_bridge.py) is validated through the same
Pydantic schemas and the same endpoint allow-list.

Security rules:
- Payloads come from the fixed SAFE_PAYLOAD allow-list in validator.py.
- Plans only reference discovered/approved endpoints.
- Unknown finding types get a read-only baseline probe that can only
  ever produce INCONCLUSIVE — never blind attacks.
"""

from __future__ import annotations

from typing import List, Optional

from app.advanced_ai.schemas import (
    DiscoveredEndpoint,
    FindingSnapshot,
    ValidationPlan,
    ValidationTestSpec,
)


# ==============================================================
# FINDING TYPE CLASSIFICATION
# ==============================================================

# (finding_type, cwe hints, keyword hints)
_TYPE_RULES = [
    ("SQL Injection", ["CWE-89"], ["sql injection", "sqli", "sql-injection", "sql inj"]),
    ("XSS", ["CWE-79"], ["xss", "cross-site scripting", "cross site scripting"]),
    ("IDOR", ["CWE-639"], ["idor", "insecure direct object", "direct object reference"]),
    ("Missing Authentication", ["CWE-306"], ["missing authentication", "unauthenticated", "no authentication"]),
    ("Broken Access Control", ["CWE-284", "CWE-285", "CWE-862"], ["broken access", "access control", "authorization", "privilege"]),
    ("Sensitive Information Exposure", ["CWE-200", "CWE-209"], ["information exposure", "information disclosure", "sensitive", "debug", "secret", "credential leak"]),
]


def classify_finding_type(finding: Optional[FindingSnapshot]) -> str:
    """
    Deterministically classify a finding into a validation category.

    Uses the finding's CWE first, then keyword matching over the
    title/vulnerability fields. Returns 'Other' when nothing matches.
    """
    if finding is None:
        return "Other"

    cwe = (finding.cwe or "").upper()
    haystack = " ".join(
        str(x) for x in (finding.title, finding.vulnerability, finding.explanation)
        if x
    ).lower()

    for ftype, cwes, keywords in _TYPE_RULES:
        if any(c in cwe for c in cwes):
            return ftype

    for ftype, _, keywords in _TYPE_RULES:
        if any(k in haystack for k in keywords):
            return ftype

    return "Other"


# ==============================================================
# ENDPOINT SELECTION HELPERS
# ==============================================================

_PARAM_PRIORITY = ("q", "query", "search", "keyword", "term", "id", "username", "name")


def _endpoints_with_params(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
    return [e for e in endpoints if e.parameters]


def _pick_injectable_endpoint(
    endpoints: List[DiscoveredEndpoint], finding: Optional[FindingSnapshot]
) -> Optional[DiscoveredEndpoint]:
    """
    Choose the most plausible endpoint for an injection-style test.

    Priority:
      1. endpoints whose path appears in the finding evidence/title
      2. endpoints with well-known injectable parameter names
      3. the first GET endpoint with parameters
    """
    candidates = _endpoints_with_params(endpoints)
    if not candidates:
        return None

    # 0. Finding's explicit target_endpoint (highest priority)
    if finding is not None and finding.target_endpoint:
        for e in candidates:
            if e.endpoint == finding.target_endpoint:
                return e

    # 1. Evidence-derived hint (e.g. evidence mentions '/api/search')
    if finding is not None:
        hint_text = " ".join(
            [finding.title or "", finding.explanation or ""] + list(finding.evidence)
        ).lower()
        for e in candidates:
            if e.endpoint.lower() in hint_text:
                return e

    # 2. Well-known parameter names
    for e in candidates:
        if any(p.lower() in _PARAM_PRIORITY for p in e.parameters):
            return e

    # 3. First GET endpoint with parameters
    for e in candidates:
        if e.method.upper() == "GET":
            return e

    return candidates[0]


def _pick_parameter(endpoint: DiscoveredEndpoint) -> str:
    """Pick the best parameter on an endpoint, preferring known names."""
    for prio in _PARAM_PRIORITY:
        for p in endpoint.parameters:
            if p.lower() == prio:
                return p
    return endpoint.parameters[0] if endpoint.parameters else ""


def _path_idor_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
    """Endpoints that look like /resource/<id> numeric-detail routes."""
    result = []
    for e in endpoints:
        if e.method.upper() != "GET":
            continue
        segments = [s for s in e.endpoint.split("/") if s]
        # matches .../users/{id} style templates or approved scope hints
        if any(seg in ("{id}", "<id>", ":id") for seg in segments):
            result.append(e)
    return result


# ==============================================================
# FALLBACK PLAN BUILDER
# ==============================================================

def build_fallback_plan(
    finding: Optional[FindingSnapshot],
    endpoints: List[DiscoveredEndpoint],
) -> ValidationPlan:
    """
    Deterministically build a safe validation plan for a finding.

    The returned plan is always executable by the validator: every
    test references a discovered/approved endpoint and uses a
    payload_kind from the fixed allow-list.
    """
    ftype = classify_finding_type(finding)

    if ftype == "SQL Injection":
        return _plan_sqli(finding, endpoints)
    if ftype == "XSS":
        return _plan_xss(finding, endpoints)
    if ftype == "IDOR":
        return _plan_idor(finding, endpoints)
    if ftype in ("Missing Authentication", "Broken Access Control"):
        return _plan_auth_boundary(finding, endpoints, ftype)
    if ftype == "Sensitive Information Exposure":
        return _plan_info_exposure(finding, endpoints)
    return _plan_safe_probe(finding, endpoints)


# --------------------------------------------------------------
# SQL INJECTION — error-based, single controlled probe + baseline
# --------------------------------------------------------------

def _plan_sqli(finding, endpoints) -> ValidationPlan:
    target = _pick_injectable_endpoint(endpoints, finding)
    if target is None:
        return _plan_safe_probe(finding, endpoints, reason=(
            "No injectable endpoint with parameters was discovered in the "
            "sandbox; falling back to a read-only baseline probe."
        ))

    param = _pick_parameter(target)
    return ValidationPlan(
        finding_type="SQL Injection",
        confidence=0.8,
        target_endpoint=target.endpoint,
        reasoning=(
            f"The finding indicates possible SQL injection. The controlled "
            f"strategy sends one benign baseline value and one single-quote "
            f"error probe to parameter '{param}' on {target.method} "
            f"{target.endpoint}, then compares observable behavior "
            f"(database error signatures vs. normal responses). No data is "
            f"extracted, modified, or destroyed."
        ),
        tests=[
            ValidationTestSpec(
                name="Baseline request (benign value)",
                method=target.method.upper(),
                endpoint=target.endpoint,
                parameter=param,
                payload_kind="benign",
                baseline=True,
                kind="error_based_sqli",
            ),
            ValidationTestSpec(
                name="Error-based SQL injection probe (single quote)",
                method=target.method.upper(),
                endpoint=target.endpoint,
                parameter=param,
                payload_kind="sqli_error_probe",
                kind="error_based_sqli",
            ),
        ],
        source="deterministic_fallback",
    )


# --------------------------------------------------------------
# XSS — benign reflection marker only (no executable script tags)
# --------------------------------------------------------------

def _plan_xss(finding, endpoints) -> ValidationPlan:
    target = _pick_injectable_endpoint(endpoints, finding)
    if target is None:
        return _plan_safe_probe(finding, endpoints, reason=(
            "No endpoint with input parameters was discovered; falling back "
            "to a read-only baseline probe."
        ))

    param = _pick_parameter(target)
    return ValidationPlan(
        finding_type="XSS",
        confidence=0.7,
        target_endpoint=target.endpoint,
        reasoning=(
            f"The finding indicates possible reflected XSS. The controlled "
            f"strategy sends a benign alphanumeric marker to parameter "
            f"'{param}' on {target.method} {target.endpoint} and checks "
            f"whether it is reflected unescaped. No script execution is "
            f"attempted."
        ),
        tests=[
            ValidationTestSpec(
                name="Baseline request (benign value)",
                method=target.method.upper(),
                endpoint=target.endpoint,
                parameter=param,
                payload_kind="benign",
                baseline=True,
                kind="reflected_xss",
            ),
            ValidationTestSpec(
                name="Reflection marker probe",
                method=target.method.upper(),
                endpoint=target.endpoint,
                parameter=param,
                payload_kind="xss_reflection_marker",
                kind="reflected_xss",
            ),
        ],
        source="deterministic_fallback",
    )


# --------------------------------------------------------------
# IDOR — compare two object IDs without credentials
# --------------------------------------------------------------

def _plan_idor(finding, endpoints) -> ValidationPlan:
    targets = _path_idor_endpoints(endpoints)
    # Fall back to any GET endpoint hinted by the finding
    if not targets:
        hinted = _pick_injectable_endpoint(endpoints, finding)
        if hinted is not None:
            targets = [hinted]

    if not targets:
        return _plan_safe_probe(finding, endpoints, reason=(
            "No object-detail endpoint was discovered; falling back to a "
            "read-only baseline probe."
        ))

    target = targets[0]
    # Concrete IDs for template endpoints
    endpoint_a = target.endpoint.replace("{id}", "1").replace(":id", "1")
    endpoint_b = target.endpoint.replace("{id}", "2").replace(":id", "2")

    return ValidationPlan(
        finding_type="IDOR",
        confidence=0.6,
        target_endpoint=target.endpoint,
        reasoning=(
            "The finding indicates possible insecure direct object "
            "reference. The controlled strategy requests two different "
            "object identifiers without elevated privileges and compares "
            "responses. If the sandbox requires credentials that Sentra "
            "does not hold, the result will be INCONCLUSIVE rather than a "
            "guess."
        ),
        tests=[
            ValidationTestSpec(
                name="Object reference A (id=1)",
                method="GET",
                endpoint=endpoint_a,
                payload_kind="none",
                baseline=True,
                kind="idor",
            ),
            ValidationTestSpec(
                name="Object reference B (id=2)",
                method="GET",
                endpoint=endpoint_b,
                payload_kind="none",
                kind="idor",
            ),
        ],
        source="deterministic_fallback",
    )


# --------------------------------------------------------------
# AUTHENTICATION / ACCESS-CONTROL BOUNDARY
# --------------------------------------------------------------

def _plan_auth_boundary(finding, endpoints, ftype) -> ValidationPlan:
    target = _pick_injectable_endpoint(endpoints, finding)
    if target is None:
        # Prefer any endpoint hinted at by the finding evidence
        for e in endpoints:
            text = " ".join(list(finding.evidence) if finding else []) + (
                (finding.title or "") if finding else ""
            )
            if e.endpoint.lower() in text.lower():
                target = e
                break
    if target is None:
        return _plan_safe_probe(finding, endpoints, reason=(
            "No candidate endpoint was discovered; falling back to a "
            "read-only baseline probe."
        ))

    return ValidationPlan(
        finding_type=ftype,
        confidence=0.6,
        target_endpoint=target.endpoint,
        reasoning=(
            f"The finding indicates a possible {ftype.lower()} issue. The "
            f"controlled strategy requests {target.method} {target.endpoint} "
            f"without any credentials and observes whether protected data "
            f"is returned (200 with content) or access is enforced "
            f"(401/403). No credentials are guessed."
        ),
        tests=[
            ValidationTestSpec(
                name="Unauthenticated access probe",
                method=target.method.upper(),
                endpoint=target.endpoint,
                payload_kind="none",
                kind="auth_boundary",
            ),
        ],
        source="deterministic_fallback",
    )


# --------------------------------------------------------------
# SENSITIVE INFORMATION EXPOSURE
# --------------------------------------------------------------

def _plan_info_exposure(finding, endpoints) -> ValidationPlan:
    target = None
    for e in endpoints:
        text = " ".join(list(finding.evidence) if finding else []) + (
            (finding.title or "") if finding else ""
        )
        if e.endpoint.lower() in text.lower():
            target = e
            break
    if target is None and endpoints:
        target = endpoints[0]
    if target is None:
        return _plan_safe_probe(finding, endpoints)

    return ValidationPlan(
        finding_type="Sensitive Information Exposure",
        confidence=0.6,
        target_endpoint=target.endpoint,
        reasoning=(
            "The finding indicates possible sensitive information "
            "exposure. The controlled strategy performs one read-only "
            "request without credentials and checks whether sensitive "
            "fields appear in the response."
        ),
        tests=[
            ValidationTestSpec(
                name="Read-only exposure probe",
                method="GET",
                endpoint=target.endpoint,
                payload_kind="none",
                kind="auth_boundary",
            ),
        ],
        source="deterministic_fallback",
    )


# --------------------------------------------------------------
# SAFE FALLBACK — read-only probe, can only be INCONCLUSIVE
# --------------------------------------------------------------

def _plan_safe_probe(finding, endpoints, reason: str = "") -> ValidationPlan:
    tests: List[ValidationTestSpec] = []
    target_endpoint = None
    if endpoints:
        first = endpoints[0]
        target_endpoint = first.endpoint
        tests.append(
            ValidationTestSpec(
                name="Read-only baseline probe",
                method="GET",
                endpoint=first.endpoint,
                payload_kind="none",
                baseline=True,
                kind="generic_probe",
            )
        )

    return ValidationPlan(
        finding_type=classify_finding_type(finding),
        confidence=0.3,
        target_endpoint=target_endpoint,
        reasoning=(
            reason or "No specific controlled validation strategy exists for "
            "this finding type; only a read-only baseline probe is performed."
        ),
        tests=tests,
        source="deterministic_fallback",
    )


# ==============================================================
# PLAN SANITIZER (applied to Gemini plans too)
# ==============================================================

_ALLOWED_METHODS = {"GET", "POST"}


def sanitize_plan(
    plan: ValidationPlan,
    allowed_endpoints: List[str],
    max_tests: int = 6,
) -> ValidationPlan:
    """
    Enforce hard constraints on any plan (Gemini or fallback).

    - method must be GET or POST
    - endpoint must be in the discovered/approved allow-list
      (exact match or template form, e.g. /api/users/{id} allows
      /api/users/1)
    - payload_kind is always one of the fixed allow-list values
      (Pydantic already enforces this)
    - caps the number of tests

    Invalid tests are dropped. The plan itself is returned mutated.
    """
    allowed = set(allowed_endpoints)

    def _endpoint_ok(ep: str) -> bool:
        if not ep.startswith("/"):
            return False
        if ep in allowed:
            return True
        # Allow concrete IDs for approved template endpoints
        for tmpl in allowed:
            if "{" in tmpl:
                prefix = tmpl.split("{", 1)[0]
                if ep.startswith(prefix) and ep[len(prefix):].strip("/").isdigit():
                    return True
        return False

    kept: List[ValidationTestSpec] = []
    for test in plan.tests[:max_tests * 2]:
        if test.method.upper() not in _ALLOWED_METHODS:
            continue
        if not _endpoint_ok(test.endpoint):
            continue
        test.method = test.method.upper()
        kept.append(test)
        if len(kept) >= max_tests:
            break

    plan.tests = kept
    return plan
