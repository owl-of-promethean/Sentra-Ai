"""
LLM Client for Sentra AI — Groq backend.

Groq (openai/gpt-oss-20b via https://api.groq.com/openai/v1) is the
intelligence layer of the system.  Python prepares the investigation
data; Groq interprets the evidence and produces a structured
SecurityFinding.

Design rules:
- Python NEVER classifies attacks.
- The LLM receives raw evidence + knowledge context.
- The LLM must reason about alternative explanations.
- A failed LLM call must never crash the investigation pipeline.

All LLM calls route through the single GroqProvider defined in
app/advanced_ai/llm_provider.py.  There is exactly one Groq client
in the process.
"""

import json
import logging
import re
import time

from app.config import Config
from app.groq_throttle import get_groq_throttle
from app.schemas import SecurityFinding

logger = logging.getLogger(__name__)


# ==============================================================
# TASK-SPECIFIC OUTPUT TOKEN LIMITS
# ==============================================================
# Groq reserves max_tokens against the TPM quota for every request,
# regardless of how many tokens the model actually generates.
# Using task-appropriate limits instead of the global 4,096 keeps
# the rolling-window TPM reservation realistic.

_INVESTIGATION_MAX_OUTPUT_TOKENS = 1_500   # SecurityFinding JSON
_AUDIT_MAX_OUTPUT_TOKENS         = 2_500   # AuditFinding[] JSON
_COPILOT_MAX_OUTPUT_TOKENS       = 1_000   # short analysis text


# ==============================================================
# INVESTIGATION PROMPT TOKEN BUDGET
# ==============================================================
# Groq TPM limit is 8,000 tokens.  The investigation prompt must stay
# comfortably below that so the response budget (max_tokens=4096) fits.
#
# Target breakdown (chars / ~tokens at 4 chars/token):
#   system instructions   ≈   900 /  225
#   metadata              ≈   400 /  100
#   trimmed features      ≈   400 /  100
#   reduced logs (≤15)    ≈ 1,500 /  375
#   knowledge (≤2500 chr) ≈ 2,500 /  625
#   output schema         ≈   750 /  190
#   ──────────────────────────────────────
#   Total                 ≈ 6,450 / 1,615  (well under 8,000)
#
# Hard cap is set at 5,500 tokens (22,000 chars) as a safety net.

_INV_MAX_LOGS           = 15     # cap raw logs (was 50)
_INV_MAX_KNOWLEDGE_CHARS = 2_500 # cap knowledge text (was unbounded)
_INV_HARD_TOKEN_LIMIT   = 5_500 # absolute ceiling for the full prompt
_INV_CHARS_PER_TOKEN    = 4      # conservative estimate

# Features keys that matter for security analysis.
_INV_FEATURE_KEYS = (
    "total_requests",
    "unique_ips",
    "unique_paths",
    "error_rate",
    "status_code_counts",
    "http_method_counts",
    "time_span_seconds",
    "requests_per_second",
)


# ==============================================================
# AUDIT PROMPT TOKEN BUDGET
# ==============================================================
# Groq TPM limit is 8,000 tokens (rolling 60-second window).
# Target prompt ≈ 3,000 tokens (~10,500 chars at 3 chars/token).
# This leaves headroom for the response and for rolling-window
# accumulation when requests are throttled with min-interval spacing.
#
# Using ~3 chars/token (conservative for mixed code + text):
#   system instructions    ≈   600 /  200
#   audit metadata         ≈   200 /   67
#   SOC context (≤300 chr) ≈   300 /  100
#   dependencies (≤5)      ≈   150 /   50
#   source snippets ≤6,000 ≈ 6,000 / 2,000
#   knowledge (≤600 chr)   ≈   600 /  200
#   output schema          ≈   600 /  200
#   headers/separators     ≈   200 /   67
#   ──────────────────────────────────────
#   Total (prompt)         ≈ 8,650 / ~2,884  (comfortable margin)
#
# Hard cap at 3,500 tokens (10,500 chars) as safety net.

_AUDIT_HARD_TOKEN_LIMIT = 3_500
_AUDIT_CHARS_PER_TOKEN  = 3
_AUDIT_MAX_CHARS        = _AUDIT_HARD_TOKEN_LIMIT * _AUDIT_CHARS_PER_TOKEN  # 10,500

# Per-section caps applied inside _build_audit_prompt.
_AUDIT_MAX_SNIPPET_CHARS   = 6_000    # source evidence (largest section)
_AUDIT_MAX_KNOWLEDGE_CHARS = 600      # reference material
_AUDIT_MAX_SOC_CHARS       = 300      # SOC investigation context


# ==============================================================
# PROMPT CONSTRUCTION
# ==============================================================

_SYSTEM_INSTRUCTIONS = """\
You are an experienced Security Operations Center (SOC) analyst.

You have been given:
1. An investigation window of HTTP/security logs and their behavioral features.
2. Contextual cybersecurity knowledge that may be relevant.

YOUR RESPONSIBILITIES:
- Treat the behavioural trigger signals as OBSERVATIONS, not conclusions.
- Reason about what the evidence might mean — consider multiple explanations.
- Do NOT classify every anomaly as an attack.
- Legitimate explanations (traffic spikes, misconfigured clients, load tests,
  health checks) must be listed alongside malicious ones.
- Express your confidence honestly. If the evidence is ambiguous, say so.
- Never invent facts not present in the logs (IPs, usernames, CVEs, endpoints).
- Base recommendations strictly on the observed evidence.

IMPORTANT:
The knowledge context tells you what patterns MAY indicate.
It is NOT evidence that any attack has occurred.
The logs and features are the actual evidence.
"""

_JSON_SCHEMA = """\
Respond with ONLY a valid JSON object — no markdown fences, no commentary.

Required JSON structure:
{
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "activity_type": "<concise label for the observed activity>",
  "confidence": <float 0.0-1.0>,
  "summary": "<one paragraph summary>",
  "evidence": ["<observation from the logs>", ...],
  "possible_explanations": ["<explanation 1>", "<explanation 2>", ...],
  "recommended_actions": ["<action 1>", ...]
}

Rules:
- severity must be exactly one of: LOW, MEDIUM, HIGH, CRITICAL
- confidence must be a number between 0.0 and 1.0
- evidence must list specific facts from the logs/features
- possible_explanations must include at least one legitimate alternative
- recommended_actions must be cautious and evidence-based
"""


def _estimate_tokens(text: str) -> int:
    """Conservative token estimate (~4 chars per token) for investigation prompts."""
    return len(text) // _INV_CHARS_PER_TOKEN + 1


def audit_estimate_tokens(text: str) -> int:
    """
    Token estimate for audit prompts (code-heavy content).

    Uses ~3 chars per token — more realistic for mixed source code
    and structured text than the 4 chars/token rate used for
    investigation (log-heavy) prompts.
    """
    return len(text) // _AUDIT_CHARS_PER_TOKEN + 1


def _deduplicate_inv_logs(logs: list[dict]) -> list[dict]:
    """Remove duplicate logs based on (source_ip, method, path, status)."""
    seen: set = set()
    unique: list[dict] = []
    for log in logs:
        key = (
            log.get("source_ip", ""),
            log.get("method", ""),
            log.get("path", ""),
            log.get("status", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(log)
    return unique


def _trim_features(features: dict) -> dict:
    """Keep only security-relevant feature keys."""
    if not isinstance(features, dict):
        return features
    return {k: features[k] for k in _INV_FEATURE_KEYS if k in features}


def _enforce_investigation_token_limit(prompt: str) -> str:
    """
    Hard safety net: if the investigation prompt exceeds the token
    budget, trim the knowledge context block (the largest variable
    section) while preserving instructions, evidence, and schema.
    """
    max_chars = _INV_HARD_TOKEN_LIMIT * _INV_CHARS_PER_TOKEN
    if len(prompt) <= max_chars:
        return prompt

    # Locate the knowledge block so we can shrink it.
    kc_start_marker = "SECURITY KNOWLEDGE CONTEXT"
    kc_end_marker = "REQUIRED OUTPUT FORMAT"
    kc_start = prompt.find(kc_start_marker)
    kc_end = prompt.find(kc_end_marker)

    if kc_start != -1 and kc_end != -1 and kc_end > kc_start:
        overhead = len(prompt) - (kc_end - kc_start)
        budget_for_kc = max_chars - overhead
        if budget_for_kc > 500:
            trimmed_kc = prompt[kc_start:kc_end][:budget_for_kc]
            trimmed_kc += "\n… [knowledge truncated for token limit]\n\n"
            return prompt[:kc_start] + trimmed_kc + prompt[kc_end:]

    # Fallback: hard-truncate the whole prompt
    return prompt[:max_chars]


def _build_investigation_prompt(investigation: dict) -> str:
    """
    Build the full LLM prompt from a complete investigation object.

    Sections are clearly separated so the model cannot confuse
    knowledge context with actual evidence.

    Token budget: the complete prompt targets ~5,000 tokens — well
    under Groq's 8,000 TPM limit for openai/gpt-oss-20b.
    """

    inv_id        = investigation.get("id", "unknown")
    window_start  = investigation.get("window_start", "unknown")
    window_end    = investigation.get("window_end", "unknown")
    log_count     = investigation.get("log_count", 0)
    trigger_score = investigation.get("trigger_score", 0)
    reasons       = investigation.get("trigger_reasons", [])
    features      = investigation.get("features", {})
    logs          = investigation.get("logs", [])
    kc            = investigation.get("knowledge_context", {})

    # ---- Section 1: instructions --------------------------------
    prompt_parts = [_SYSTEM_INSTRUCTIONS, ""]

    # ---- Section 2: investigation metadata ----------------------
    prompt_parts.append("=" * 40)
    prompt_parts.append("OBSERVED INVESTIGATION DATA")
    prompt_parts.append("=" * 40)
    prompt_parts.append(f"Investigation ID : {inv_id}")
    prompt_parts.append(f"Window           : {window_start} -> {window_end}")
    prompt_parts.append(f"Log count        : {log_count}")
    prompt_parts.append(f"Trigger score    : {trigger_score}")
    prompt_parts.append(
        f"Trigger signals  : {', '.join(reasons) if reasons else 'none'}"
    )
    prompt_parts.append("")

    # ---- Section 3: behavioural features (trimmed) ---------------
    prompt_parts.append("--- BEHAVIORAL FEATURES ---")
    trimmed = _trim_features(features)
    if trimmed:
        for key, value in trimmed.items():
            prompt_parts.append(f"  {key}: {value}")
    else:
        prompt_parts.append("  (no features calculated)")
    prompt_parts.append("")

    # ---- Section 4: raw logs (deduplicated, capped at 15) --------
    deduped_logs = _deduplicate_inv_logs(logs)
    sample_logs = deduped_logs[:_INV_MAX_LOGS]
    omitted = len(logs) - len(sample_logs)
    prompt_parts.append(
        f"--- RAW LOGS (sample: {len(sample_logs)} of {log_count}, "
        f"{len(deduped_logs)} unique) ---"
    )
    if sample_logs:
        for i, log in enumerate(sample_logs, start=1):
            prompt_parts.append(
                f"  [{i}] {log.get('timestamp','?')} | "
                f"{log.get('source_ip','?')} | "
                f"{log.get('method','?')} {log.get('path','?')} | "
                f"HTTP {log.get('status','?')}"
            )
    else:
        prompt_parts.append("  (no logs available)")
    if omitted > 0:
        prompt_parts.append(f"  ({omitted} additional logs omitted)")
    prompt_parts.append("")

    # ---- Section 5: knowledge context (capped) -------------------
    prompt_parts.append("=" * 40)
    prompt_parts.append("SECURITY KNOWLEDGE CONTEXT")
    prompt_parts.append(
        "(Reference material only — not evidence that any attack occurred)"
    )
    prompt_parts.append("=" * 40)
    kc_status  = kc.get("status", "unknown")
    kc_sources = kc.get("sources", [])
    kc_text    = kc.get("context", "")

    if kc_status in ("success", "partial") and kc_text:
        prompt_parts.append(
            f"Sources loaded: {', '.join(kc_sources) if kc_sources else 'none'}"
        )
        prompt_parts.append("")
        if len(kc_text) > _INV_MAX_KNOWLEDGE_CHARS:
            prompt_parts.append(kc_text[:_INV_MAX_KNOWLEDGE_CHARS])
            prompt_parts.append(
                f"\n… [{len(kc_text) - _INV_MAX_KNOWLEDGE_CHARS} chars of "
                f"reference material truncated]"
            )
        else:
            prompt_parts.append(kc_text)
    else:
        prompt_parts.append(
            f"Knowledge retrieval status: {kc_status}. "
            "No additional context available."
        )
    prompt_parts.append("")

    # ---- Section 6: output schema -------------------------------
    prompt_parts.append("=" * 40)
    prompt_parts.append("REQUIRED OUTPUT FORMAT")
    prompt_parts.append("=" * 40)
    prompt_parts.append(_JSON_SCHEMA)

    return "\n".join(prompt_parts)


def _extract_json(raw_text: str) -> str:
    """
    Extract the first JSON object from the LLM response text.

    Handles cases where the model wraps the JSON in markdown fences
    or adds commentary before/after it.
    """
    # Strip markdown code fences if present
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if fenced:
        return fenced.group(1)

    # Otherwise find the first { ... } block
    brace_start = raw_text.find("{")
    brace_end   = raw_text.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        return raw_text[brace_start : brace_end + 1]

    return raw_text  # Return as-is and let json.loads raise


def _extract_json_array(raw_text: str) -> str:
    """
    Extract the first JSON array from the LLM response text.

    Used for the code audit response which returns a list of findings.
    Falls back to returning the raw text so json.loads can raise a
    clear error.
    """
    # Strip markdown fences
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw_text, re.DOTALL)
    if fenced:
        return fenced.group(1)

    bracket_start = raw_text.find("[")
    bracket_end   = raw_text.rfind("]")
    if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
        return raw_text[bracket_start : bracket_end + 1]

    return raw_text


def _is_truncated_json_error(exc: Exception, raw_text: str) -> bool:
    """
    Detect whether a JSON parse error is likely due to response truncation.

    Truncation indicators:
    - "Unterminated string" in error message
    - "Expecting value" near end of text
    - "Expecting ',' delimiter" near end
    - Unclosed brackets/braces
    - finish_reason was "length" (checked separately)

    Returns True if the error appears to be from truncation, False otherwise.
    """
    err_msg = str(exc).lower()

    # Common truncation patterns from json.JSONDecodeError
    truncation_patterns = [
        "unterminated string",
        "expecting value",
        "expecting ',' delimiter",
        "expecting ':' delimiter",
        "unexpected end of",
        "end of file",
    ]

    for pattern in truncation_patterns:
        if pattern in err_msg:
            return True

    # Check if array/object is not properly closed
    if raw_text:
        stripped = raw_text.strip()
        if stripped.startswith("[") and not stripped.endswith("]"):
            return True
        if stripped.startswith("{") and not stripped.endswith("}"):
            return True

    return False


# ==============================================================
# SECURITY-RELEVANT FILE PRIORITY  (used by snippet selector)
# ==============================================================
# File-path patterns scored by security relevance.
# Higher score = more security-critical = selected first.
# Generic / catch-all patterns score 0.

_SECURITY_HIGH_PATTERNS = (
    "route", "api", "controller", "view", "endpoint",
    "auth", "login", "session", "token", "oauth",
    "database", "model", "query", "schema", "migration",
    "middleware", "permission", "access", "admin",
    "user", "account", "password",
)

_SECURITY_MEDIUM_PATTERNS = (
    "config", "setting", "template", "render",
    "request", "response", "param", "input", "form",
    "upload", "file", "handler", "service",
    "security", "csrf", "cors", "encrypt",
    "app", "main", "server", "init",
)

_LOW_VALUE_PATTERNS = (
    "test", "spec", "mock", "fixture", "conftest",
    "readme", "changelog", "license", "doc", "example",
    "migrate", "generate", "script", "setup", "lint",
    "build", "dist", "__init__", "manage",
    "_patch", "_fix", "_apply", "_demo",
    "staging", "diagnostic",
)


def _security_priority(file_path: str, language: str) -> int:
    """
    Return a priority score (0–30) for security-relevant file selection.

    Higher score = selected first when building the audit prompt.
    Generic or low-value files (tests, docs, staging) score 0.
    This is a generic pattern-based heuristic — no specific vulnerability
    or endpoint is hardcoded.
    """
    fp_lower = file_path.lower()

    # Deprioritize low-value files
    for pat in _LOW_VALUE_PATTERNS:
        if pat in fp_lower:
            return 0

    basename = fp_lower.rsplit("/", 1)[-1] if "/" in fp_lower else fp_lower

    score = 0
    for pat in _SECURITY_HIGH_PATTERNS:
        if pat in basename:
            score += 15
            break

    for pat in _SECURITY_MEDIUM_PATTERNS:
        if pat in basename:
            score += 8
            break

    # Also check the full path for structural hints
    if any(d in fp_lower for d in ("routes/", "auth/", "api/", "controllers/",
                                     "models/", "database/", "db/")):
        score += 10

    # Bonus for security-relevant languages
    if language in ("python", "javascript", "typescript", "php", "java",
                    "ruby", "go", "sql"):
        score += 5

    return score


def _compress_code(code: str) -> str:
    """
    Compress whitespace in source code without changing semantics.

    - Collapses 3+ consecutive blank lines into 2.
    - Strips trailing whitespace from each line.
    """
    if not code:
        return code
    lines = code.split("\n")
    compressed = []
    blank_count = 0
    for line in lines:
        stripped = line.rstrip()
        if not stripped:
            blank_count += 1
            if blank_count <= 2:
                compressed.append("")
        else:
            blank_count = 0
            compressed.append(stripped)
    return "\n".join(compressed)


# ==============================================================
# AUDIT PROMPT CONSTRUCTION
# ==============================================================

_AUDIT_SYSTEM_INSTRUCTIONS = """\
You are an application security engineer auditing source code.

You have:
1. Source-code snippets (OBSERVED EVIDENCE — facts from project files).
2. Technologies and dependencies.
3. Optional SOC investigation context.
4. Security reference material (CWE/OWASP) as REFERENCE only.

RULES:
- Identify vulnerabilities directly observable in the evidence.
- Cite exact file and line number from the evidence for each finding.
- Classify with CWE/OWASP where applicable.
- Provide actionable remediation.
- Do NOT invent file paths, line numbers, or source code.
- Do NOT flag code you have not been shown.
- Do NOT claim a vulnerability solely from reference material.
- If evidence is insufficient, say so with low confidence.
- Legitimate patterns must not be reported as findings.

EVIDENCE vs. REFERENCE:
  OBSERVED EVIDENCE = facts.  REFERENCE = informational only.
  Findings must be supported by OBSERVED EVIDENCE.
"""

_AUDIT_JSON_SCHEMA = """\
Respond with ONLY a valid JSON array — no markdown, no commentary.
Each element:
[
  {
    "title": "<short title>",
    "vulnerability": "<category, e.g. SQL Injection>",
    "cwe": "<CWE-ID or null>",
    "owasp": "<OWASP category or null>",
    "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "confidence": <0.0-1.0>,
    "explanation": "<why vulnerable — based on evidence>",
    "evidence": ["<observation from source code>", ...],
    "location": {
      "file_path": "<from evidence>",
      "start_line": <int>, "end_line": <int>,
      "snippet": "<vulnerable code lines>"
    },
    "remediation": "<concrete fix>",
    "references": ["<CWE/OWASP URL>", ...]
  }
]
Rules:
- Return [] if no vulnerabilities found.
- severity: LOW|MEDIUM|HIGH|CRITICAL only.
- confidence: float 0.0-1.0.
- evidence: specific facts from provided source code.
- file_path and line numbers from evidence only, never invented.
- Do not duplicate findings for the same location.
"""


def _build_audit_prompt(audit_context: dict) -> str:
    """
    Build the LLM prompt for a code audit.

    audit_context must contain:
      audit_id          - str
      investigation_id  - str (may be None)
      soc_context       - dict (SOC investigation summary, may be empty)
      technologies      - list[str]
      dependencies      - list[dict]  (name, version, manager)
      source_snippets   - list[dict]  (file_path, start_line, end_line, language, code)
      knowledge_context - dict        (status, sources, context)
    """
    audit_id   = audit_context.get("audit_id", "unknown")
    inv_id     = audit_context.get("investigation_id", "none")
    techs      = audit_context.get("technologies", [])
    deps       = audit_context.get("dependencies", [])
    snippets   = audit_context.get("source_snippets", [])
    kc         = audit_context.get("knowledge_context", {})
    soc        = audit_context.get("soc_context", {})

    parts = [_AUDIT_SYSTEM_INSTRUCTIONS, ""]

    # ---- Section 1: audit metadata --------------------------------
    parts.append("=" * 40)
    parts.append("AUDIT METADATA")
    parts.append("=" * 40)
    parts.append(f"Audit ID         : {audit_id}")
    parts.append(f"Investigation ID : {inv_id}")
    parts.append(f"Technologies     : {', '.join(techs) if techs else 'unknown'}")
    parts.append("")

    # ---- Section 2: SOC context (if available, capped) -------------
    if soc:
        parts.append("--- SOC CONTEXT ---")
        trigger_reasons = soc.get("trigger_reasons", [])
        tr_str = ", ".join(trigger_reasons)
        if len(tr_str) > 150:
            tr_str = tr_str[:150] + "…"
        parts.append(f"  Trigger reasons : {tr_str}")
        parts.append(f"  Trigger score   : {soc.get('trigger_score', 0)}")
        if soc.get("finding"):
            f = soc["finding"]
            parts.append(f"  SOC severity    : {f.get('severity', '?')}")
            parts.append(f"  Activity type   : {f.get('activity_type', '?')}")
        parts.append("")

    # ---- Section 3: dependencies (capped at 10) --------------------
    if deps:
        parts.append("--- DEPENDENCIES ---")
        for d in deps[:5]:  # cap at 5 to stay within token budget
            ver = d.get("version") or "unspecified"
            mgr = d.get("manager", "?")
            parts.append(f"  [{mgr}] {d.get('name', '?')} {ver}")
        if len(deps) > 5:
            parts.append(f"  … ({len(deps) - 5} more omitted)")
        parts.append("")

    # ---- Section 4: observed source-code evidence -----------------
    parts.append("=" * 40)
    parts.append("OBSERVED EVIDENCE — SOURCE CODE SNIPPETS")
    parts.append("(These are facts from the actual project files)")
    parts.append("=" * 40)

    if snippets:
        snippet_chars = 0
        included = 0
        for snippet in snippets:
            fp   = snippet.get("file_path", "unknown")
            sl   = snippet.get("start_line", 1)
            el   = snippet.get("end_line", sl)
            lang = snippet.get("language", "")
            code = _compress_code(snippet.get("code", ""))

            # Per-section cap: stop adding snippets once budget exhausted
            if snippet_chars + len(code) > _AUDIT_MAX_SNIPPET_CHARS:
                remaining = _AUDIT_MAX_SNIPPET_CHARS - snippet_chars
                if remaining > 200:  # only include if meaningful
                    code = code[:remaining]
                else:
                    parts.append(
                        f"\n… ({len(snippets) - included} more "
                        f"files truncated for token limit)"
                    )
                    break

            parts.append(f"\n-- File: {fp}  Lines: {sl}-{el}  Language: {lang} --")
            parts.append(code)
            snippet_chars += len(code)
            included += 1
    else:
        parts.append("(no source-code snippets were provided)")
    parts.append("")

    # ---- Section 5: security reference material -------------------
    parts.append("=" * 40)
    parts.append("SECURITY REFERENCE MATERIAL")
    parts.append("(Reference only — not evidence of vulnerability in this project)")
    parts.append("=" * 40)
    kc_status = kc.get("status", "unknown")
    kc_text   = kc.get("context", "")

    if kc_status in ("success", "partial") and kc_text:
        sources = kc.get("sources", [])
        parts.append(f"Sources: {', '.join(sources) if sources else 'none'}")
        parts.append("")
        if len(kc_text) > _AUDIT_MAX_KNOWLEDGE_CHARS:
            parts.append(kc_text[:_AUDIT_MAX_KNOWLEDGE_CHARS])
            parts.append(
                f"\n… [{len(kc_text) - _AUDIT_MAX_KNOWLEDGE_CHARS} chars of "
                f"reference material truncated]"
            )
        else:
            parts.append(kc_text)
    else:
        parts.append(f"Knowledge retrieval status: {kc_status}. No reference available.")
    parts.append("")

    # ---- Section 6: output schema ---------------------------------
    parts.append("=" * 40)
    parts.append("REQUIRED OUTPUT FORMAT")
    parts.append("=" * 40)
    parts.append(_AUDIT_JSON_SCHEMA)

    return "\n".join(parts)


def _enforce_audit_token_limit(prompt: str) -> str:
    """
    Hard safety net: if the assembled audit prompt exceeds the token
    budget, deterministically trim the largest variable sections while
    preserving system instructions and the required output schema.

    Trimming order (most expendable first):
      1. Knowledge context  (reference material, not evidence)
      2. Source snippets    (largest section; trim from the end)

    Never truncated:
      - _AUDIT_SYSTEM_INSTRUCTIONS  (the instruction block)
      - _AUDIT_JSON_SCHEMA          (the required output format)
    """
    max_chars = _AUDIT_MAX_CHARS  # 15,300
    if len(prompt) <= max_chars:
        return prompt

    # Section markers used to locate trimmable regions.
    evidence_marker  = "OBSERVED EVIDENCE"
    reference_marker = "SECURITY REFERENCE MATERIAL"
    schema_marker    = "REQUIRED OUTPUT FORMAT"

    # -- Step 1: shrink the knowledge / reference section ---------------
    ref_start = prompt.find(reference_marker)
    schema_start = prompt.find(schema_marker)

    if ref_start != -1 and schema_start != -1 and schema_start > ref_start:
        overhead = len(prompt) - (schema_start - ref_start)
        budget_for_ref = max_chars - overhead
        if budget_for_ref > 200:
            trimmed = prompt[ref_start:schema_start][:budget_for_ref]
            trimmed += "\n\u2026 [reference material truncated for token limit]\n\n"
            prompt = prompt[:ref_start] + trimmed + prompt[schema_start:]

    if len(prompt) <= max_chars:
        return prompt

    # -- Step 2: shrink the source evidence section ---------------------
    ev_start = prompt.find(evidence_marker)
    # Re-locate reference marker in case Step 1 changed offsets.
    ref_start = prompt.find(reference_marker)

    if ev_start != -1 and ref_start != -1 and ref_start > ev_start:
        overhead = len(prompt) - (ref_start - ev_start)
        budget_for_ev = max_chars - overhead
        if budget_for_ev > 300:
            trimmed = prompt[ev_start:ref_start][:budget_for_ev]
            trimmed += "\n\u2026 [source evidence truncated for token limit]\n\n"
            prompt = prompt[:ev_start] + trimmed + prompt[ref_start:]

    if len(prompt) <= max_chars:
        return prompt

    # -- Step 3: fallback — hard-truncate the middle of the prompt ------
    # Keep the first ~3,000 chars (instructions + metadata) and the last
    # ~2,500 chars (output schema), drop everything in between.
    head = 3_000
    tail = 2_500
    if len(prompt) > head + tail + 100:
        return (
            prompt[:head]
            + "\n\n\u2026 [middle sections truncated for token limit]\n\n"
            + prompt[-tail:]
        )

    return prompt[:max_chars]


# ==============================================================
# GROQ-BACKED LLM CLIENT
# ==============================================================


class GeminiClient:
    """
    LLM client for Sentra AI analysis — backed by Groq.

    The class name is preserved for backward compatibility with
    existing tests and call sites.  Internally all calls route
    through the shared GroqProvider (one OpenAI client in the
    process).
    """

    def __init__(self) -> None:
        """Initialise the underlying Groq provider."""
        from app.advanced_ai.llm_provider import get_llm_provider
        self._provider = get_llm_provider()

    # ----------------------------------------------------------
    # THROTTLED GENERATION WITH EMPTY-RESPONSE RETRY
    # ----------------------------------------------------------

    _RETRY_DELAY = 1.0  # seconds between retries for empty responses

    def _generate_with_retry(
        self,
        prompt: str,
        timeout: float = 30.0,
        max_tokens: int | None = None,
    ) -> dict:
        """
        Throttled LLM call with one retry on empty response.

        1. Estimates input tokens from the prompt length.
        2. Acquires the rolling-TPM throttle (input + output tokens)
           so the request fits inside the 60-second window.
        3. Calls the provider with the task-appropriate max_tokens.
        4. If the response is empty (provider returned success=False
           with 'empty response' in the error), retries once — going
           through the same TPM limiter.
        5. Returns the provider's response dict unchanged for all
           other cases.
        """
        throttle = get_groq_throttle()
        input_tokens = audit_estimate_tokens(prompt)
        output_tokens = max_tokens or _AUDIT_MAX_OUTPUT_TOKENS

        throttle.acquire(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        try:
            response = self._provider.generate(
                prompt, timeout=timeout, max_tokens=max_tokens,
            )
        except Exception as exc:
            return {"success": False, "error": f"LLM provider error: {exc}"}

        # Retry once on empty/no-content response (but NOT on content-filter).
        # New diagnostic error messages use specific patterns:
        #   "returned no choices"    → transient, retry
        #   "content is None"        → transient, retry
        #   "content is empty string"→ transient, retry
        #   "content filter"         → blocked, do NOT retry
        _err = response.get("error", "").lower()
        _retryable = (
            not response.get("success")
            and "content filter" not in _err
            and (
                "no choices" in _err
                or "content is none" in _err
                or "content is empty" in _err
            )
        )
        if _retryable:
            time.sleep(self._RETRY_DELAY)
            throttle.acquire(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            try:
                response = self._provider.generate(
                    prompt, timeout=timeout, max_tokens=max_tokens,
                )
            except Exception as exc:
                return {"success": False, "error": f"LLM provider error: {exc}"}

        return response

    # ----------------------------------------------------------
    # PRIMARY METHOD: full investigation analysis
    # ----------------------------------------------------------

    def analyze_investigation(self, investigation: dict) -> dict:
        """
        Send a complete investigation object to the LLM and return
        a structured SecurityFinding.

        Args:
            investigation: The investigation dict from handle_investigation_trigger(),
                           including logs, features, trigger_reasons, and
                           knowledge_context.

        Returns:
            {"success": True,  "finding": <SecurityFinding as dict>}
            {"success": False, "error":   "<reason>"}
        """
        prompt = _build_investigation_prompt(investigation)
        prompt = _enforce_investigation_token_limit(prompt)  # hard safety net

        response = self._generate_with_retry(
            prompt,
            timeout=30.0,
            max_tokens=_INVESTIGATION_MAX_OUTPUT_TOKENS,
        )

        if not response.get("success"):
            return response

        raw_text = response["text"]

        # Parse and validate the response
        try:
            json_str = _extract_json(raw_text)
            data     = json.loads(json_str)

            # Link the finding back to its investigation
            data["investigation_id"] = investigation.get("id")

            finding = SecurityFinding(**data)
            return {"success": True, "finding": finding.model_dump()}

        except Exception as exc:
            return {
                "success": False,
                "error": f"Response parse/validation error: {exc}",
                "raw_response": raw_text,
            }

    # ----------------------------------------------------------
    # CODE AUDIT ANALYSIS
    # ----------------------------------------------------------

    def analyze_code_audit(self, audit_context: dict) -> dict:
        """
        Send a prepared audit context to the LLM and return a list of
        structured AuditFinding dicts.

        Args:
            audit_context: Prepared by AuditEngine._build_audit_context().
                           Must contain source_snippets, technologies,
                           dependencies, knowledge_context, and optional
                           soc_context.

        Returns:
            {"success": True,  "findings": [<AuditFinding dict>, ...]}
            {"success": False, "error":    "<reason>",
                               "raw_response": "<raw text if available>"}
        """
        # Import here to avoid circular import (audit_schemas -> llm)
        from app.audit_schemas import AuditFinding, CodeLocation

        prompt = _build_audit_prompt(audit_context)
        prompt = _enforce_audit_token_limit(prompt)  # hard safety net

        response = self._generate_with_retry(
            prompt,
            timeout=30.0,
            max_tokens=_AUDIT_MAX_OUTPUT_TOKENS,
        )

        if not response.get("success"):
            # Translate empty-content provider errors into a clear audit
            # message.  Other failures (API errors, timeouts, content filter)
            # are returned unchanged so the audit engine records them verbatim.
            _err = response.get("error", "").lower()
            if ("content is none" in _err
                    or "content is empty" in _err
                    or "no choices" in _err):
                logger.warning(
                    "Audit LLM returned empty response after retry: %s",
                    response.get("error", "")[:200],
                )
                return {
                    "success": False,
                    "error": (
                        "AI audit unavailable: Groq returned an empty "
                        "response after retry."
                    ),
                }
            return response

        raw_text = response["text"]
        finish_reason = response.get("finish_reason", "unknown")

        # --- Diagnostic logging (non-sensitive metadata only) ---
        response_len = len(raw_text) if raw_text else 0
        estimated_output_tokens = response_len // 3  # ~3 chars/token for code
        logger.info(
            "Audit response: length=%d chars, est_tokens=%d, "
            "finish_reason=%s, max_tokens_budget=%d",
            response_len, estimated_output_tokens,
            finish_reason, _AUDIT_MAX_OUTPUT_TOKENS,
        )

        # --- Check for truncation signal from provider ---
        was_truncated = (finish_reason == "length")
        if was_truncated:
            logger.warning(
                "Audit response TRUNCATED by provider (finish_reason='length'). "
                "Response length: %d chars, budget: %d tokens. "
                "Will attempt one retry with same context.",
                response_len, _AUDIT_MAX_OUTPUT_TOKENS,
            )

        # --- Attempt to parse, retry once on truncation ---
        parse_result = self._parse_audit_response(raw_text)

        if parse_result.get("success"):
            logger.info("Audit JSON parse success: %d findings",
                       len(parse_result.get("findings", [])))
            return parse_result

        # Parse failed — check if it looks like truncation
        parse_error = parse_result.get("error", "")
        is_truncation = was_truncated or _is_truncated_json_error(
            Exception(parse_error), raw_text
        )

        if is_truncation:
            logger.warning(
                "Audit JSON parse failed (likely truncation): %s. "
                "Attempting ONE retry through TPM throttle.",
                parse_error[:200],  # cap error length in log
            )
            # Retry once through the rolling TPM throttle
            retry_response = self._generate_with_retry(
                prompt,
                timeout=30.0,
                max_tokens=_AUDIT_MAX_OUTPUT_TOKENS,
            )
            if retry_response.get("success"):
                retry_text = retry_response["text"]
                retry_finish = retry_response.get("finish_reason", "unknown")
                logger.info(
                    "Audit retry response: length=%d chars, finish_reason=%s",
                    len(retry_text) if retry_text else 0, retry_finish,
                )
                retry_result = self._parse_audit_response(retry_text)
                if retry_result.get("success"):
                    logger.info("Audit retry JSON parse success: %d findings",
                               len(retry_result.get("findings", [])))
                    return retry_result
                # Retry also failed — report both failures
                return {
                    "success": False,
                    "error": (
                        f"Audit JSON parse failed after retry. "
                        f"First: {parse_error[:100]}. "
                        f"Retry: {retry_result.get('error', 'unknown')[:100]}. "
                        f"finish_reason={retry_finish}. "
                        f"max_tokens={_AUDIT_MAX_OUTPUT_TOKENS} may be insufficient."
                    ),
                    "raw_response": retry_text,
                }
            # Retry LLM call failed
            return {
                "success": False,
                "error": (
                    f"Audit JSON parse failed and retry failed. "
                    f"Parse error: {parse_error[:100]}. "
                    f"Retry error: {retry_response.get('error', 'unknown')[:100]}"
                ),
                "raw_response": raw_text,
            }

        # Not a truncation error — return the original parse failure
        return parse_result

    def _parse_audit_response(self, raw_text: str) -> dict:
        """
        Parse the raw LLM text into a list of AuditFinding dicts.

        Returns:
            {"success": True,  "findings": [<dict>, ...]}
            {"success": False, "error": "<reason>", "raw_response": "<text>"}
        """
        from app.audit_schemas import AuditFinding, CodeLocation

        try:
            json_str = _extract_json_array(raw_text)
            data = json.loads(json_str)

            if not isinstance(data, list):
                return {
                    "success": False,
                    "error": f"Expected JSON array, got {type(data).__name__}",
                    "raw_response": raw_text,
                }

            findings = []
            for item in data:
                # Validate/coerce each finding via the Pydantic model
                loc_data = item.pop("location", None)
                location = None
                if isinstance(loc_data, dict):
                    try:
                        location = CodeLocation(**loc_data)
                    except Exception:
                        location = None
                try:
                    finding = AuditFinding(location=location, **item)
                    findings.append(finding.model_dump())
                except Exception:
                    # Skip malformed individual findings rather than
                    # discarding the whole response
                    continue

            return {"success": True, "findings": findings}

        except Exception as exc:
            return {
                "success": False,
                "error": f"Audit response parse/validation error: {exc}",
                "raw_response": raw_text,
            }

    # ----------------------------------------------------------
    # LEGACY METHOD: kept for backward compatibility
    # ----------------------------------------------------------

    def analyze_security_event(
        self,
        logs: list[dict],
        context: str = ""
    ) -> dict:
        """
        Original simple analysis method (pre-Day-3).

        Kept intact so existing call sites are not broken.
        New code should use analyze_investigation() instead.
        """
        prompt = self._build_prompt(logs, context)

        response = self._generate_with_retry(
            prompt,
            timeout=30.0,
            max_tokens=_COPILOT_MAX_OUTPUT_TOKENS,
        )

        if not response.get("success"):
            return response

        return {"success": True, "analysis": response["text"]}

    def _build_prompt(self, logs: list[dict], context: str) -> str:
        """Legacy prompt builder used by analyze_security_event()."""

        return f"""
You are an experienced Security Operations Center (SOC) analyst.

You are analyzing a short investigation window of HTTP/security logs.

Your job is NOT to blindly classify every unusual request as an attack.

Instead:

1. Examine the events collectively.
2. Look for suspicious behavior or meaningful correlations.
3. Determine whether the activity deserves investigation.
4. Explain the evidence behind your conclusion.
5. If there is insufficient evidence, say so clearly.
6. Do not invent facts that are not present in the logs.

For potentially suspicious activity, provide:

- Severity: LOW / MEDIUM / HIGH / CRITICAL
- Attack or activity category
- Confidence from 0.0 to 1.0
- Summary
- Evidence
- Recommended analyst actions

For benign or inconclusive activity, explain why it does not currently
provide enough evidence of a security incident.

Investigation context:
{context if context else "No additional context provided."}

Logs:
{self._format_logs(logs)}
"""

    @staticmethod
    def _format_logs(logs: list[dict]) -> str:
        """Convert logs into a compact format for the LLM."""

        if not logs:
            return "No logs were received."

        lines = []
        for index, log in enumerate(logs, start=1):
            lines.append(
                f"\nLog #{index}\n"
                f"timestamp: {log.get('timestamp', 'unknown')}\n"
                f"source_ip: {log.get('source_ip', 'unknown')}\n"
                f"method: {log.get('method', 'unknown')}\n"
                f"path: {log.get('path', 'unknown')}\n"
                f"status: {log.get('status', 'unknown')}\n"
                f"user_agent: {log.get('user_agent', 'unknown')}\n"
            )
        return "\n".join(lines)


# ==============================================================
# MODULE-LEVEL SINGLETON + CONVENIENCE FUNCTIONS
# ==============================================================

_gemini_client: GeminiClient | None = None


def get_gemini_client() -> GeminiClient:
    """Return the shared LLM client instance (Groq-backed)."""

    global _gemini_client

    if _gemini_client is None:
        _gemini_client = GeminiClient()

    return _gemini_client


def analyze_security_event(
    logs: list[dict],
    context: str = ""
) -> dict:
    """Legacy convenience function — delegates to GeminiClient."""

    return get_gemini_client().analyze_security_event(
        logs=logs,
        context=context,
    )


def analyze_investigation(investigation: dict) -> dict:
    """
    Convenience function: analyze a full investigation object.

    Returns {"success": True,  "finding": <dict>} or
            {"success": False, "error":   <str>}.
    """

    return get_gemini_client().analyze_investigation(investigation)


def analyze_code_audit(audit_context: dict) -> dict:
    """
    Convenience function: run a code audit analysis.

    Returns {"success": True,  "findings": [<dict>, ...]} or
            {"success": False, "error":    <str>}.
    """

    return get_gemini_client().analyze_code_audit(audit_context)


def build_audit_prompt(audit_context: dict) -> str:
    """
    Convenience function: build the audit prompt without making an LLM call.
    Useful for testing prompt construction.
    """
    return _build_audit_prompt(audit_context)
