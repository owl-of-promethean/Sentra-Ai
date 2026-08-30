"""
LLM reasoning bridge for Advanced AI [BETA].

Groq (via app/advanced_ai/llm_provider.py) is the REASONING layer
only. It:
  - analyzes a finding + discovered attack surface,
  - selects the appropriate validation strategy,
  - generates a structured JSON test plan,
  - interprets collected evidence,
  - explains its conclusion.

The provider NEVER performs HTTP requests, executes code, or supplies
payloads. Payload selection stays with the deterministic validator's
fixed allow-list (payload_kind only). Every Groq response is
validated with Pydantic; malformed or untrusted output triggers a
graceful fallback to the deterministic planner/evaluator.

Both functions return {"success": False, ...} on any failure so the
pipeline can degrade instead of crashing.
"""

from __future__ import annotations

import json
from typing import List

from app.advanced_ai.llm_provider import (
    LLMProviderError,
    _extract_json,
    get_llm_provider,
)
from app.advanced_ai.schemas import (
    DiscoveredEndpoint,
    FindingSnapshot,
    TestEvidence,
    ValidationPlan,
    ValidationResult,
)
from app.advanced_ai.events import log_event


# ==============================================================
# PROMPT: VALIDATION PLANNING
# ==============================================================

_PLAN_INSTRUCTIONS = """\
You are the planning layer of a controlled security-validation system.

You are given ONE security finding (from a code audit or SOC
investigation) and the attack surface discovered inside an authorized
sandbox. Your job is to choose the appropriate CONTROLLED validation
strategy for this finding.

HARD RULES:
- You do NOT execute anything. A deterministic engine executes your plan.
- Only reference endpoints from the DISCOVERED ATTACK SURFACE list.
- method must be GET or POST.
- payload_kind must be one of: "none", "benign", "sqli_error_probe",
  "xss_reflection_marker". You may NOT invent payloads.
- Use the MINIMUM number of tests needed (1-3). Include a benign
  baseline test when comparing behavior.
- If the finding type has no safe controlled test, return an empty
  tests array and explain why in reasoning.
- SQL Injection findings -> error-based probe (sqli_error_probe) with
  a benign baseline on the injectable parameter.
- XSS findings -> reflection marker probe (xss_reflection_marker).
- IDOR / access-control findings -> compare object references without
  privilege escalation.

Respond with ONLY a valid JSON object — no markdown fences:
{
  "finding_type": "<e.g. SQL Injection>",
  "confidence": <float 0.0-1.0>,
  "target_endpoint": "<one endpoint from the attack surface>",
  "reasoning": "<why this strategy is appropriate for this finding>",
  "tests": [
    {
      "name": "<short test name>",
      "method": "GET",
      "endpoint": "<endpoint from the attack surface>",
      "parameter": "<parameter name or null>",
      "payload_kind": "<none|benign|sqli_error_probe|xss_reflection_marker>",
      "baseline": <true only for benign comparison requests>,
      "kind": "<error_based_sqli|reflected_xss|idor|auth_boundary|generic_probe>"
    }
  ]
}
"""

_EVAL_INSTRUCTIONS = """\
You are the evaluation layer of a controlled security-validation
system.

You are given a validation plan and the evidence collected by the
deterministic engine while executing it inside an authorized sandbox.

Classify the result strictly as one of:
  VULNERABLE   - the reported weakness IS observable in the sandbox
  MITIGATED    - the sandbox demonstrably defends against the probe
  INCONCLUSIVE - the evidence is insufficient to decide

HARD RULES:
- Sending an attack string is NOT proof of vulnerability. Only
  OBSERVABLE behavioral differences count (e.g. a database error after
  the probe but not after the benign baseline).
- If requests failed or evidence is missing, return INCONCLUSIVE.
- Be honest about confidence.
- Provide a concrete, safe remediation when relevant.

Respond with ONLY a valid JSON object — no markdown fences:
{
  "verdict": "<VULNERABLE|MITIGATED|INCONCLUSIVE>",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<evidence-grounded explanation>",
  "remediation": "<concrete safe fix or null>"
}
"""


def _format_finding(finding: FindingSnapshot) -> str:
    if finding is None:
        return "(no finding provided)"
    loc = ""
    if finding.file_path:
        loc = f"\nSource location: {finding.file_path}"
        if finding.line:
            loc += f" line {finding.line}"
    evidence = "\n".join(f"  - {e}" for e in finding.evidence[:5]) or "  (none)"
    return (
        f"Title: {finding.title}\n"
        f"Vulnerability: {finding.vulnerability or finding.title}\n"
        f"CWE: {finding.cwe or 'unknown'}\n"
        f"OWASP: {finding.owasp or 'unknown'}\n"
        f"Severity: {finding.severity or 'unknown'}\n"
        f"Explanation: {finding.explanation or '(none)'}\n"
        f"Observed evidence:\n{evidence}{loc}"
    )


def _format_endpoints(endpoints: List[DiscoveredEndpoint]) -> str:
    if not endpoints:
        return "(no attack surface discovered)"
    lines = []
    for e in endpoints[:20]:
        params = ", ".join(e.parameters) if e.parameters else "-"
        lines.append(
            f"  {e.method} {e.endpoint}  params=[{params}]  "
            f"auth={e.authentication}"
        )
    return "\n".join(lines)


# ==============================================================
# PLANNING
# ==============================================================

def plan_via_gemini(
    finding: FindingSnapshot,
    endpoints: List[DiscoveredEndpoint],
    soc_context: dict = None,
    timeout: int = 30,
) -> dict:
    """
    Ask the configured LLM provider to generate a structured
    validation plan.

    Returns:
        {"success": True,  "plan": ValidationPlan}
        {"success": False, "error": str}
    """
    soc_section = ""
    if soc_context:
        reasons = ", ".join(soc_context.get("trigger_reasons", [])) or "none"
        f = soc_context.get("finding") or {}
        soc_section = (
            "\nSOC INVESTIGATION CONTEXT\n"
            f"  Trigger reasons: {reasons}\n"
            f"  SOC activity type: {f.get('activity_type', 'unknown')}\n"
            f"  SOC severity: {f.get('severity', 'unknown')}\n"
        )

    prompt = (
        _PLAN_INSTRUCTIONS
        + "\n" + "=" * 60 + "\nFINDING TO VALIDATE\n" + "=" * 60 + "\n"
        + _format_finding(finding)
        + "\n" + soc_section
        + "\n" + "=" * 60 + "\nDISCOVERED ATTACK SURFACE (the ONLY endpoints "
        "you may reference)\n" + "=" * 60 + "\n"
        + _format_endpoints(endpoints)
    )

    try:
        provider = get_llm_provider()
        response = provider.generate(prompt, timeout=timeout)
    except LLMProviderError as exc:
        return {"success": False, "error": f"LLM provider unavailable: {exc}"}
    except Exception as exc:  # absolute safety net — never crash the job
        return {"success": False, "error": f"LLM provider error: {exc}"}

    if not response.get("success"):
        return response

    try:
        data = json.loads(_extract_json(response["text"]))
        plan = ValidationPlan(**data)
        plan.source = provider.name
        if not plan.tests:
            return {
                "success": False,
                "error": f"{provider.display_name} returned an empty test list",
            }
        return {"success": True, "plan": plan}
    except Exception as exc:
        return {
            "success": False,
            "error": f"Plan parse/validation error: {exc}",
        }


# ==============================================================
# EVIDENCE EVALUATION
# ==============================================================

def evaluate_via_gemini(
    finding: FindingSnapshot,
    plan: ValidationPlan,
    evidence: List[TestEvidence],
    timeout: int = 30,
) -> dict:
    """
    Ask the configured LLM provider to interpret collected evidence.

    Returns:
        {"success": True,  "result": ValidationResult}
        {"success": False, "error": str}
    """
    plan_str = json.dumps(plan.model_dump(), default=str, indent=2)
    ev_lines = []
    for e in evidence:
        ev_lines.append(json.dumps(e.model_dump(mode="json"), default=str))
    evidence_str = "\n".join(ev_lines) or "(no evidence collected)"

    prompt = (
        _EVAL_INSTRUCTIONS
        + "\n" + "=" * 60 + "\nFINDING UNDER VALIDATION\n" + "=" * 60 + "\n"
        + _format_finding(finding)
        + "\n" + "=" * 60 + "\nVALIDATION PLAN\n" + "=" * 60 + "\n"
        + plan_str
        + "\n" + "=" * 60 + "\nCOLLECTED EVIDENCE (facts from the sandbox)\n"
        + "=" * 60 + "\n" + evidence_str
    )

    try:
        provider = get_llm_provider()
        response = provider.generate(prompt, timeout=timeout)
    except LLMProviderError as exc:
        return {"success": False, "error": f"LLM provider unavailable: {exc}"}
    except Exception as exc:  # absolute safety net — never crash the job
        return {"success": False, "error": f"LLM provider error: {exc}"}

    if not response.get("success"):
        return response

    try:
        data = json.loads(_extract_json(response["text"]))
        # ValidationResult enforces the verdict Literal and bounds.
        result = ValidationResult(
            verdict=data.get("verdict", "INCONCLUSIVE"),
            confidence=float(data.get("confidence", 0.0)),
            reasoning=str(data.get("reasoning", "")),
            remediation=data.get("remediation"),
            source=provider.name,
        )
        return {"success": True, "result": result}
    except Exception as exc:
        return {
            "success": False,
            "error": f"Evaluation parse/validation error: {exc}",
        }
