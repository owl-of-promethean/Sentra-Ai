"""
Deterministic validation engine for Advanced AI [BETA].

Executes a validated ValidationPlan against the sandbox and collects
evidence. This is the ONLY component that performs HTTP requests —
Gemini never executes anything.

Safety rules:
- Payloads come exclusively from the SAFE_PAYLOADS allow-list below.
  There is no mechanism to inject arbitrary payloads.
- Only GET and POST are supported; methods/endpoints must already be
  in the allow-list built from the crawl + approved scopes.
- Request budget is hard-capped.
- Evidence is redacted (cookies, tokens, secrets) before storage.
"""

from __future__ import annotations

import re
import time
from typing import List, Optional, Set

import httpx

from app.advanced_ai.events import log_event
from app.advanced_ai.schemas import TestEvidence, ValidationPlan


# ==============================================================
# SAFE PAYLOAD ALLOW-LIST
# ==============================================================

SAFE_PAYLOADS = {
    # No payload — plain request.
    "none": None,
    # Benign baseline value.
    "benign": "sentinel",
    # Error-based SQLi probe: a single quote breaks naive string
    # interpolation and produces a database error WITHOUT extracting,
    # modifying, or destroying any data.
    "sqli_error_probe": "'",
    # Alphanumeric reflection marker — never an executable script.
    "xss_reflection_marker": "sentinelxss9f3a",
}

# Hard limits
MAX_REQUESTS_PER_JOB = 10
BODY_SUMMARY_LIMIT = 400

# Database error signatures used for deterministic observation.
DB_ERROR_SIGNATURES = [
    "sqlite3.operationalerror",
    "operationalerror",
    "unrecognized token",
    "sql syntax",
    "syntax error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-",
    "mysql_",
    "mariadb",
    "postgresql",
    "psycopg2",
    "you have an error in your sql",
]

# Sensitive markers used for information-exposure observation.
_SENSITIVE_KEYS = ["secret_key", "password", "api_key", "private_key", "token"]

# Redaction patterns for stored evidence.
_REDACTIONS = [
    (re.compile(r"(?i)(set-cookie:\s*)([^\r\n;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\"?(?:password|token|secret|api_key|authorization)\"?\s*[:=]\s*)\"?[^\s\",}]+"), r"\1[REDACTED]"),
]


def redact_text(text: str) -> str:
    """Remove obvious secrets from text before storing it as evidence."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# ==============================================================
# EXECUTOR
# ==============================================================

class ValidationExecutor:
    """
    Runs the controlled tests of a ValidationPlan against the sandbox.

    Args:
        base_url:    sandbox base URL (registry-resolved).
        timeout:     per-request timeout in seconds.
        transport:   optional httpx transport (tests inject MockTransport).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 5.0,
        transport=None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def execute(
        self,
        plan: ValidationPlan,
        allowed_endpoints: Set[str],
    ) -> List[TestEvidence]:
        """
        Execute every test in the plan, collecting evidence.

        Args:
            plan:              sanitized ValidationPlan.
            allowed_endpoints: set of discovered/approved paths that
                               tests may touch (defense in depth —
                               sanitize_plan already filtered these).

        Returns:
            List of TestEvidence, one per attempted test.
        """
        evidence: List[TestEvidence] = []
        requests_left = MAX_REQUESTS_PER_JOB

        log_event(
            "validation_started",
            finding_type=plan.finding_type,
            tests=len(plan.tests),
        )

        with httpx.Client(
            timeout=self.timeout,
            transport=self.transport,
            follow_redirects=False,
        ) as client:
            for test in plan.tests:
                if requests_left <= 0:
                    evidence.append(TestEvidence(
                        test_name=test.name,
                        endpoint=test.endpoint,
                        method=test.method,
                        observation="Request budget exhausted — test skipped.",
                        simulated=True,
                    ))
                    continue

                # Endpoint allow-list re-check at execution time.
                if not self._endpoint_allowed(test.endpoint, allowed_endpoints):
                    evidence.append(TestEvidence(
                        test_name=test.name,
                        endpoint=test.endpoint,
                        method=test.method,
                        observation=(
                            "Test skipped: endpoint is not in the "
                            "discovered/approved allow-list."
                        ),
                        simulated=True,
                    ))
                    continue

                requests_left -= 1
                evidence.append(self._run_single_test(client, test))

        log_event(
            "validation_completed",
            tests_attempted=len(evidence),
            requests_used=MAX_REQUESTS_PER_JOB - requests_left,
        )
        return evidence

    # ----------------------------------------------------------
    # SINGLE TEST EXECUTION
    # ----------------------------------------------------------

    def _run_single_test(self, client: httpx.Client, test) -> TestEvidence:
        payload = SAFE_PAYLOADS.get(test.payload_kind)
        method = test.method.upper()
        url = self.base_url + test.endpoint

        start = time.perf_counter()
        status: Optional[int] = None
        headers = {}
        body = ""
        error: Optional[str] = None

        try:
            if method == "GET":
                params = {test.parameter: payload} if (test.parameter and payload is not None) else None
                resp = client.get(
                    url,
                    params=params,
                    headers={"User-Agent": "Sentinel-AdvancedAI-Validator/0.1"},
                )
            else:  # POST
                data = {test.parameter: payload} if (test.parameter and payload is not None) else {}
                resp = client.post(
                    url,
                    data=data,
                    headers={"User-Agent": "Sentinel-AdvancedAI-Validator/0.1"},
                )
            status = resp.status_code
            headers = dict(resp.headers)
            body = resp.text or ""
        except httpx.TimeoutException:
            error = "request timed out"
        except Exception as exc:
            error = f"transport error: {exc}"

        elapsed_ms = int((time.perf_counter() - start) * 1000)

        # ---- Build deterministic observation -------------------------
        body_lower = body.lower()
        indicators: List[str] = []
        observations: List[str] = []

        if error:
            observations.append(f"Request failed: {error}.")
        else:
            observations.append(f"HTTP {status} after {elapsed_ms} ms.")

            # Database error signatures (SQLi error-based detection)
            if any(sig in body_lower for sig in DB_ERROR_SIGNATURES):
                indicators.append("db_error_signature")
                observations.append(
                    "Response contains a database error signature "
                    "following the controlled input."
                )

            # Reflection of the XSS marker (unescaped)
            if payload and test.payload_kind == "xss_reflection_marker":
                if payload in body:
                    indicators.append("unescaped_reflection")
                    observations.append(
                        "The benign marker was reflected back unescaped in "
                        "the response body."
                    )

            # Sensitive content exposure
            if any(k in body_lower for k in _SENSITIVE_KEYS):
                indicators.append("sensitive_content")
                observations.append(
                    "Response body appears to contain sensitive fields."
                )

            # Auth enforcement observation
            if status in (401, 403):
                indicators.append("auth_enforced")
                observations.append("Access was denied by the application.")
            elif test.kind in ("idor", "auth_boundary") and status == 200:
                indicators.append("data_returned_unauthenticated")
                observations.append(
                    "Content returned without presenting credentials."
                )

        # ---- Redact and truncate the body summary --------------------
        summary = redact_text(body[:BODY_SUMMARY_LIMIT])
        summary = " ".join(summary.split())  # collapse whitespace

        return TestEvidence(
            test_name=test.name,
            endpoint=test.endpoint,
            method=method,
            parameter=test.parameter,
            payload_kind=test.payload_kind,
            status=status,
            response_time_ms=elapsed_ms,
            content_type=headers.get("content-type"),
            body_summary=summary,
            observation=" ".join(observations),
            indicators=indicators,
            simulated=False,
        )

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------

    @staticmethod
    def _endpoint_allowed(endpoint: str, allowed_endpoints: Set[str]) -> bool:
        if not endpoint.startswith("/"):
            return False
        if endpoint in allowed_endpoints:
            return True
        for tmpl in allowed_endpoints:
            if "{" in tmpl:
                prefix = tmpl.split("{", 1)[0]
                if endpoint.startswith(prefix) and endpoint[len(prefix):].strip("/").isdigit():
                    return True
        return False
