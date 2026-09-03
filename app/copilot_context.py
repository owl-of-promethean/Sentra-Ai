"""
Copilot context builder — keeps Groq requests within the 8,000 TPM limit.

The Copilot endpoint (POST /copilot/ask) builds a prompt that includes a
serialized security context object.  Without reduction, investigations
with full knowledge_context (~45K chars of Markdown), 20 raw logs, and
verbose features easily exceed 12,000 tokens — well above the Groq
8,000 TPM ceiling for openai/gpt-oss-20b.

This module provides:

  * estimate_tokens()      — fast char-based token estimate (~4 chars/token)
  * build_copilot_context()— type-aware context reduction (investigation,
                             audit, advanced_ai_job)
  * build_copilot_prompt() — assembles the final prompt string
  * enforce_token_limit()  — hard safety cap at MAX_CONTEXT_TOKENS

Reduction priority (highest → lowest):
  1. Current user question           (never truncated)
  2. Current security finding/event  (core identity fields preserved)
  3. Relevant endpoint/path
  4. Relevant recent logs/evidence   (capped, deduplicated, slim fields)
  5. Relevant remediation
  6. Other historical/context info   (summarized or dropped)
  7. Raw knowledge text              (truncated aggressively)

Design rules:
  - No LLM calls for summarization — all reduction is local.
  - No frontend/UI changes.
  - The existing Groq provider remains untouched.
  - The response format is unchanged.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# ==============================================================
# TOKEN BUDGET
# ==============================================================

# Conservative token estimate: ~4 chars per token for English text and
# JSON structure.  Groq's tokenizer may differ slightly, but this gives
# a safe upper bound.
CHARS_PER_TOKEN = 4

# Hard ceiling for the *context* portion of the prompt (everything
# except the system instruction and the analyst question).
# Target: total prompt comfortably under 8,000 tokens.
#   system_instruction ≈ 100 tokens
#   question           ≈ 50–200 tokens
#   context            ≤ 5,500 tokens  ← this constant
#   JSON overhead      ≈ 200 tokens
#   ─────────────────────────────────────
#   Total              ≈ 5,850–6,000 tokens (safe margin of ~2,000)
MAX_CONTEXT_TOKENS = 5_500

# Maximum characters for the serialized context (derived from budget).
MAX_CONTEXT_CHARS = MAX_CONTEXT_TOKENS * CHARS_PER_TOKEN  # 22,000

# Sub-budgets (in characters) for individual sections.
_MAX_KNOWLEDGE_CHARS = 2_000       # knowledge_context.context text
_MAX_LOG_COUNT = 10                # investigation logs cap
_MAX_LOG_CHARS_EACH = 300         # per-log character cap
_MAX_FINDING_COUNT = 8             # audit findings cap
_MAX_FINDING_EVIDENCE = 3          # evidence items per finding
_MAX_FINDING_EVIDENCE_CHARS = 150  # chars per evidence string
_MAX_REMEDIATION_CHARS = 300       # per-finding remediation cap
_MAX_EXPLANATION_CHARS = 400       # per-finding explanation cap
_MAX_AA_EVIDENCE_COUNT = 5         # advanced_ai evidence items cap


# ==============================================================
# TOKEN ESTIMATION
# ==============================================================


def estimate_tokens(text: str) -> int:
    """Return a conservative token estimate for *text*."""
    return len(text) // CHARS_PER_TOKEN + 1


# ==============================================================
# LOG REDUCTION
# ==============================================================

# Fields to keep from each log entry — strips headers, body, user_agent
# noise, and other verbose metadata.
_LOG_SLIM_FIELDS = (
    "timestamp", "ingested_at", "source_ip", "method",
    "path", "status", "query_params",
)


def _slim_log(log: dict) -> dict:
    """Return a compact copy of a log entry with only security-relevant fields."""
    return {k: log[k] for k in _LOG_SLIM_FIELDS if k in log}


def _deduplicate_logs(logs: List[dict]) -> List[dict]:
    """Remove duplicate logs based on (source_ip, method, path, status)."""
    seen: set = set()
    unique: List[dict] = []
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


def _reduce_logs(logs: List[dict]) -> tuple[List[dict], int]:
    """
    Deduplicate, slim, and cap logs.

    Returns (reduced_logs, original_count).
    """
    original_count = len(logs)
    deduped = _deduplicate_logs(logs)
    slimmed = [_slim_log(lg) for lg in deduped]
    capped = slimmed[:_MAX_LOG_COUNT]
    return capped, original_count


# ==============================================================
# KNOWLEDGE CONTEXT REDUCTION
# ==============================================================


def _reduce_knowledge(kc: Any) -> Any:
    """
    Truncate the knowledge_context to a safe character budget.

    Keeps status and sources intact; truncates the context text.
    """
    if not isinstance(kc, dict):
        return kc

    ctx_text = kc.get("context", "")
    if len(ctx_text) > _MAX_KNOWLEDGE_CHARS:
        kc = dict(kc)
        kc["context"] = (
            ctx_text[:_MAX_KNOWLEDGE_CHARS]
            + f"\n… [truncated — {len(ctx_text) - _MAX_KNOWLEDGE_CHARS} chars removed]"
        )
    return kc


# ==============================================================
# FEATURES REDUCTION
# ==============================================================

# Only keep the most security-relevant feature fields.
_FEATURE_SLIM_KEYS = (
    "total_requests",
    "unique_ips",
    "unique_paths",
    "error_rate",
    "requests_per_second",
    "status_code_counts",
)


def _reduce_features(features: Any) -> Any:
    """Return a compact subset of the features dict."""
    if not isinstance(features, dict):
        return features
    return {k: features[k] for k in _FEATURE_SLIM_KEYS if k in features}


# ==============================================================
# INVESTIGATION CONTEXT REDUCTION
# ==============================================================


def _reduce_investigation(ctx: dict) -> dict:
    """Build a compact investigation dict for the Copilot prompt."""
    out: dict = {}

    # Priority 1-2: identity + core event fields
    for key in ("id", "display_id", "created_at", "window_start", "window_end",
                "status", "trigger_score", "trigger_reasons"):
        if key in ctx:
            out[key] = ctx[key]

    # Priority 3-4: logs (reduced)
    logs = ctx.get("logs", [])
    reduced_logs, orig_count = _reduce_logs(logs)
    out["logs"] = reduced_logs
    out["_logs_note"] = (
        f"(showing {len(reduced_logs)} of {orig_count} total logs)"
    )

    # Priority 4: features (reduced)
    if "features" in ctx:
        out["features"] = _reduce_features(ctx["features"])

    # Priority 5: log_count (scalar)
    if "log_count" in ctx:
        out["log_count"] = ctx["log_count"]

    # Priority 6: knowledge_context (reduced)
    if "knowledge_context" in ctx:
        out["knowledge_context"] = _reduce_knowledge(ctx["knowledge_context"])

    return out


# ==============================================================
# AUDIT CONTEXT REDUCTION
# ==============================================================


def _truncate(text: Optional[str], max_chars: int) -> Optional[str]:
    """Truncate a string to *max_chars*, appending an ellipsis if trimmed."""
    if text is None:
        return None
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "…"


def _reduce_finding(f: Any) -> dict:
    """Return a compact copy of one audit finding."""
    if isinstance(f, dict):
        d = f
    else:
        # Pydantic model — use model_dump
        d = f.model_dump() if hasattr(f, "model_dump") else dict(f)

    out: dict = {}
    for key in ("finding_id", "title", "vulnerability", "cwe", "owasp",
                "severity", "confidence"):
        if key in d:
            out[key] = d[key]

    # Explanation (truncated)
    out["explanation"] = _truncate(d.get("explanation"), _MAX_EXPLANATION_CHARS)

    # Evidence (capped count + truncated per item)
    evidence = d.get("evidence", [])
    out["evidence"] = [
        _truncate(e, _MAX_FINDING_EVIDENCE_CHARS)
        for e in evidence[:_MAX_FINDING_EVIDENCE]
    ]
    if len(evidence) > _MAX_FINDING_EVIDENCE:
        out["_evidence_note"] = (
            f"({len(evidence) - _MAX_FINDING_EVIDENCE} more evidence items omitted)"
        )

    # Remediation (truncated)
    out["remediation"] = _truncate(d.get("remediation"), _MAX_REMEDIATION_CHARS)

    # Location (compact)
    loc = d.get("location")
    if loc:
        if hasattr(loc, "model_dump"):
            loc = loc.model_dump()
        out["location"] = {
            k: loc[k] for k in ("file_path", "start_line", "end_line") if k in loc
        }

    return out


def _reduce_audit(ctx: dict) -> dict:
    """Build a compact audit dict for the Copilot prompt."""
    out: dict = {}

    # Identity + status
    for key in ("audit_id", "display_id", "investigation_id",
                "investigation_display_id", "app_id", "app_name",
                "environment", "scan_type", "status", "files_scanned",
                "technologies", "error"):
        if key in ctx:
            out[key] = ctx[key]

    # Dependencies: keep count, drop full list
    deps = ctx.get("dependencies", [])
    out["dependencies_count"] = len(deps)
    if deps:
        # Keep just the top 5 dependency names for context
        dep_names = []
        for d in deps[:5]:
            if isinstance(d, dict):
                dep_names.append(d.get("name", "?"))
            elif hasattr(d, "name"):
                dep_names.append(d.name)
        out["top_dependencies"] = dep_names

    # Findings (capped + reduced)
    findings = ctx.get("findings", [])
    out["findings"] = [
        _reduce_finding(f) for f in findings[:_MAX_FINDING_COUNT]
    ]
    if len(findings) > _MAX_FINDING_COUNT:
        out["_findings_note"] = (
            f"(showing {_MAX_FINDING_COUNT} of {len(findings)} total findings)"
        )

    # Timestamps
    for key in ("created_at", "completed_at"):
        if key in ctx:
            out[key] = ctx[key]

    return out


# ==============================================================
# ADVANCED AI JOB CONTEXT REDUCTION
# ==============================================================


def _reduce_advanced_ai_job(ctx: dict) -> dict:
    """Build a compact advanced_ai_job dict for the Copilot prompt."""
    out: dict = {}

    # Identity + status
    for key in ("job_id", "display_id", "status", "app_id", "app_name",
                "environment", "investigation_id", "investigation_display_id",
                "audit_id", "audit_display_id", "error"):
        if key in ctx:
            out[key] = ctx[key]

    # Finding snapshot (compact)
    finding = ctx.get("finding")
    if finding:
        if hasattr(finding, "model_dump"):
            finding = finding.model_dump()
        slim: dict = {}
        for key in ("finding_id", "title", "vulnerability", "cwe", "owasp",
                     "severity", "confidence", "target_endpoint", "origin"):
            if key in finding:
                slim[key] = finding[key]
        slim["explanation"] = _truncate(
            finding.get("explanation"), _MAX_EXPLANATION_CHARS
        )
        out["finding"] = slim

    # Result (compact — keep verdict + summary, drop raw data)
    result = ctx.get("result")
    if result:
        if hasattr(result, "model_dump"):
            result = result.model_dump()
        out["result"] = {
            k: result[k] for k in ("verdict", "summary", "confidence")
            if k in result
        }

    # Plan (compact — keep summary, drop full steps)
    plan = ctx.get("plan")
    if plan:
        if hasattr(plan, "model_dump"):
            plan = plan.model_dump()
        plan_slim = {k: plan[k] for k in ("strategy", "target_endpoint") if k in plan}
        steps = plan.get("steps", [])
        plan_slim["step_count"] = len(steps)
        out["plan"] = plan_slim

    # Evidence (capped, no raw bodies)
    evidence = ctx.get("evidence", [])
    ev_list = []
    for ev in evidence[:_MAX_AA_EVIDENCE_COUNT]:
        if hasattr(ev, "model_dump"):
            ev = ev.model_dump()
        ev_list.append({
            k: ev[k] for k in ("kind", "endpoint", "status_code", "summary")
            if k in ev
        })
    out["evidence"] = ev_list
    if len(evidence) > _MAX_AA_EVIDENCE_COUNT:
        out["_evidence_note"] = (
            f"(showing {_MAX_AA_EVIDENCE_COUNT} of {len(evidence)} evidence items)"
        )

    # Attack surface: just count
    attack_surface = ctx.get("attack_surface", [])
    out["attack_surface_count"] = len(attack_surface)

    # Fix status
    for key in ("fix_status", "created_at", "completed_at"):
        if key in ctx:
            out[key] = ctx[key]

    return out


# ==============================================================
# PUBLIC: BUILD REDUCED CONTEXT
# ==============================================================


def build_copilot_context(context_type: str, context_obj: dict) -> dict:
    """
    Return a size-reduced copy of *context_obj* suitable for the
    Copilot prompt.

    Args:
        context_type: One of 'investigation', 'audit', 'advanced_ai_job'.
        context_obj:  The full context dict from the backend.

    Returns:
        A new dict with verbose fields trimmed, capped, or removed.
    """
    if context_type == "investigation":
        return _reduce_investigation(context_obj)
    elif context_type == "audit":
        return _reduce_audit(context_obj)
    elif context_type == "advanced_ai_job":
        return _reduce_advanced_ai_job(context_obj)
    else:
        # Unknown type — return as-is but still enforce the hard cap
        return dict(context_obj)


# ==============================================================
# PUBLIC: BUILD PROMPT
# ==============================================================

_SYSTEM_INSTRUCTION = (
    "You are Sentra Copilot, an AI assistant embedded in a Security Operations platform.\n"
    "You are NOT a general-purpose assistant.\n"
    "You MUST only answer questions that are directly related to the Sentra security context "
    "object supplied below.\n"
    "If the question is unrelated to the supplied security context, refuse politely and "
    "briefly (one sentence) without providing any other information.\n"
    "Do not provide programming help, general knowledge, entertainment, or anything outside "
    "the supplied security context.\n"
    "Be concise, precise, and professional."
)


def build_copilot_prompt(
    context_type: str,
    reduced_context: dict,
    question: str,
) -> str:
    """
    Assemble the final prompt string for Groq.

    Uses compact JSON (no indent) to minimize token usage.
    """
    # Compact JSON — separators with no extra whitespace
    ctx_str = json.dumps(reduced_context, default=str, separators=(",", ":"))

    return (
        f"{_SYSTEM_INSTRUCTION}\n\n"
        f"{'=' * 40}\n"
        f"SENTRA SECURITY CONTEXT ({context_type.upper()})\n"
        f"{'=' * 40}\n"
        f"{ctx_str}\n\n"
        f"{'=' * 40}\n"
        f"ANALYST QUESTION\n"
        f"{'=' * 40}\n"
        f"{question}\n"
    )


# ==============================================================
# PUBLIC: HARD TOKEN SAFETY
# ==============================================================


def enforce_token_limit(prompt: str, max_tokens: int = MAX_CONTEXT_TOKENS) -> str:
    """
    Hard safety net: if the full prompt exceeds *max_tokens*, trim the
    serialized context JSON from the middle while preserving the system
    instruction and the analyst question.

    This is a last-resort safeguard — build_copilot_context() should
    already keep the prompt well within limits.

    Returns the (possibly trimmed) prompt.
    """
    max_chars = max_tokens * CHARS_PER_TOKEN
    if len(prompt) <= max_chars:
        return prompt

    # Locate the context block boundaries so we trim context, not question.
    ctx_start_marker = "SENTRA SECURITY CONTEXT"
    question_marker = "ANALYST QUESTION"

    ctx_start = prompt.find(ctx_start_marker)
    question_start = prompt.find(question_marker)

    if ctx_start == -1 or question_start == -1 or question_start <= ctx_start:
        # Fallback: hard-truncate the whole prompt
        return prompt[:max_chars]

    # How many chars are available for the context block?
    overhead = len(prompt) - (question_start - ctx_start)
    budget_for_ctx = max_chars - overhead

    if budget_for_ctx < 500:
        # Extremely tight — just keep the question
        return prompt[:ctx_start] + "[context omitted — too large]\n\n" + prompt[question_start:]

    # Trim the context block
    ctx_end = question_start
    trimmed_ctx = prompt[ctx_start:ctx_end][:budget_for_ctx]
    if len(trimmed_ctx) < (ctx_end - ctx_start):
        trimmed_ctx += "\n… [context truncated for token limit]\n"

    return prompt[:ctx_start] + trimmed_ctx + "\n" + prompt[question_start:]
