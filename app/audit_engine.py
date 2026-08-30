"""
Audit engine for SOC-AI Phase 2.

Orchestrates the full Quick Scan pipeline:
  1. Crawl the source directory (SourceCrawler)
  2. Detect technologies and dependencies (DependencyDetector)
  3. Select relevant source-code snippets (up to TOKEN_BUDGET)
  4. Retrieve local security reference knowledge (AuditKnowledgeRetriever)
  5. Send prepared context to Gemini (GeminiClient.analyze_code_audit)
  6. Validate and return structured AuditFinding list

Design rules:
- Python prepares evidence; Gemini reasons about it.
- Python NEVER declares something a vulnerability.
- Evidence from source code is strictly separated from reference knowledge.
- Gemini receives relevant snippets only, not the entire repository.
- A failed Gemini call must never lose the audit record.
- All operations are synchronous; async callers use run_in_executor.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

from app.audit_schemas import (
    AuditFinding,
    AuditKnowledgeQuery,
    AuditResult,
    DependencyInfo,
)
from app.audit_retriever import retrieve_audit_knowledge
from app.dependency_detector import DependencyDetector
from app.source_crawler import CrawlResult, SourceCrawler, SourceFile


# ==============================================================
# SNIPPET SELECTION LIMITS
# ==============================================================

# Maximum total characters of source code collected by the snippet
# selector.  The *prompt-level* cap (_AUDIT_MAX_SNIPPET_CHARS in llm.py)
# is 6,000 — these module-level values control how much raw
# code is collected as candidates before the prompt builder trims.
MAX_SNIPPET_CHARS  = 4_000

# Maximum lines per individual file snippet.
MAX_LINES_PER_FILE = 60

# Maximum number of files whose snippets are included.
MAX_FILES_IN_PROMPT = 6


# ==============================================================
# AUDIT ENGINE
# ==============================================================


class AuditEngine:
    """
    Runs a Quick Scan code audit for a given source directory.

    Usage:
        engine = AuditEngine()
        result = engine.run_quick_scan(audit_result, investigation)
        # result is the updated AuditResult (mutated in-place + returned)
    """

    def __init__(
        self,
        crawler: Optional[SourceCrawler] = None,
        detector: Optional[DependencyDetector] = None,
    ) -> None:
        self.crawler  = crawler  or SourceCrawler()
        self.detector = detector or DependencyDetector()

    # ----------------------------------------------------------
    # PUBLIC: Quick Scan
    # ----------------------------------------------------------

    def run_quick_scan(
        self,
        audit_result: AuditResult,
        investigation: Optional[dict] = None,
    ) -> AuditResult:
        """
        Run a Quick Scan audit using only local source code and knowledge.

        Mutates audit_result in-place:
          - status -> "analyzing" then "complete" / "failed"
          - files_scanned, technologies, dependencies, findings, completed_at

        Args:
            audit_result:  The AuditResult created by POST /audit/request.
            investigation: The linked SOC investigation dict (may be None).

        Returns:
            The updated AuditResult.
        """
        return self._run_scan(
            audit_result,
            investigation,
            max_files=MAX_FILES_IN_PROMPT,
            max_lines=MAX_LINES_PER_FILE,
            max_chars=MAX_SNIPPET_CHARS,
            include_investigation_logs=False,
        )

    # ----------------------------------------------------------
    # PUBLIC: Deep Scan
    # ----------------------------------------------------------

    def run_deep_scan(
        self,
        audit_result: AuditResult,
        investigation: Optional[dict] = None,
    ) -> AuditResult:
        """
        Run a Deep Scan audit with extended source coverage and full
        investigation context (including raw logs and SOC finding).

        Compared to Quick Scan:
          - More raw files collected (15 vs 6 files, 120 vs 60 lines).
          - Larger raw snippet budget (15k vs 4k chars).
          - Investigation raw logs are included as additional context.
          - SOC finding (if available) is included in full.

        NOTE: The *prompt-level* cap in llm.py (_AUDIT_MAX_SNIPPET_CHARS)
        ensures that regardless of how much raw data is collected here,
        the assembled LLM prompt stays within the 3,500-token budget.

        Args:
            audit_result:  The AuditResult created by POST /audit/request.
            investigation: The linked SOC investigation dict (may be None).

        Returns:
            The updated AuditResult.
        """
        return self._run_scan(
            audit_result,
            investigation,
            max_files=15,
            max_lines=120,
            max_chars=15_000,
            include_investigation_logs=True,
        )

    # ----------------------------------------------------------
    # INTERNAL: Shared scan pipeline
    # ----------------------------------------------------------

    def _run_scan(
        self,
        audit_result: AuditResult,
        investigation: Optional[dict],
        *,
        max_files: int,
        max_lines: int,
        max_chars: int,
        include_investigation_logs: bool,
    ) -> AuditResult:
        """
        Shared scan pipeline for both Quick and Deep scans.
        """
        audit_result.status = "analyzing"

        try:
            # Step 1: crawl source directory
            source_path = audit_result.source_path
            if not source_path:
                raise ValueError("source_path is required for scan")

            crawl = self.crawler.crawl(source_path)
            audit_result.files_scanned = crawl.file_count

            # Step 2: detect technologies and dependencies
            deps, techs = self.detector.detect(crawl)
            audit_result.technologies = techs
            audit_result.dependencies = deps

            # Step 3: build knowledge query
            trigger_reasons = (
                (investigation or {}).get("trigger_reasons", [])
            )
            query = AuditKnowledgeQuery(
                technologies=techs,
                packages=deps,
                trigger_context=trigger_reasons,
                # CWE/OWASP hints are intentionally empty at query time —
                # Gemini will identify them from evidence, not the other way round.
            )

            # Step 4: retrieve local security knowledge
            knowledge_context = retrieve_audit_knowledge(query)

            # Step 5: select representative source snippets
            snippets = self._select_snippets(
                crawl,
                max_files=max_files,
                max_lines=max_lines,
                max_chars=max_chars,
            )

            # Step 6: build the audit context for Gemini
            soc_summary = self._summarise_investigation(
                investigation,
                include_logs=include_investigation_logs,
            )
            audit_context = self._build_audit_context(
                audit_result=audit_result,
                snippets=snippets,
                deps=deps,
                techs=techs,
                knowledge_context=knowledge_context,
                soc_summary=soc_summary,
            )

            # Step 7: call Gemini (import inline to keep dependency clear)
            from app.llm import analyze_code_audit
            result = analyze_code_audit(audit_context)

            if result.get("success"):
                raw_findings = result.get("findings", [])
                # Validate each finding through the Pydantic model
                validated = []
                for f in raw_findings:
                    try:
                        validated.append(AuditFinding(**f))
                    except Exception:
                        continue
                audit_result.findings    = validated
                audit_result.status      = "complete"
            else:
                audit_result.status = "failed"
                audit_result.error  = result.get("error", "Unknown Gemini error")

        except Exception as exc:
            audit_result.status = "failed"
            audit_result.error  = str(exc)

        audit_result.completed_at = datetime.now(timezone.utc)
        return audit_result

    # ----------------------------------------------------------
    # SNIPPET SELECTION
    # ----------------------------------------------------------

    def _select_snippets(
        self,
        crawl: CrawlResult,
        *,
        max_files: int = MAX_FILES_IN_PROMPT,
        max_lines: int = MAX_LINES_PER_FILE,
        max_chars: int = MAX_SNIPPET_CHARS,
    ) -> List[dict]:
        """
        Select a representative subset of source-code snippets to send
        to the LLM.  Total character budget is max_chars.

        Selection strategy:
        1. Filter out low-value files (tests, docs, generated, staging)
        2. Score remaining files by security relevance (routes, auth, DB, etc.)
        3. Sort by priority score descending, then file size descending
        4. Cap at max_lines lines per file
        5. Stop accumulating once max_chars is reached

        Returns a list of dicts:
          {"file_path", "start_line", "end_line", "language", "code"}
        """
        from app.llm import _security_priority, _compress_code

        # Filter out low-value files and score by security relevance
        candidates: List[tuple[int, SourceFile]] = []
        for sf in crawl.files:
            priority = _security_priority(sf.rel_path, sf.language)
            if priority > 0:
                candidates.append((priority, sf))

        # If too few candidates after filtering, add all non-empty files
        if len(candidates) < max_files:
            seen = {sf.abs_path for _, sf in candidates}
            for sf in crawl.files:
                if sf.abs_path not in seen and sf.size_bytes > 0:
                    priority = _security_priority(sf.rel_path, sf.language)
                    candidates.append((priority, sf))

        # Sort: security priority descending, then file size descending
        candidates.sort(key=lambda x: (-x[0], -x[1].size_bytes))

        snippets: List[dict] = []
        total_chars = 0

        for priority, sf in candidates[:max_files]:
            if total_chars >= max_chars:
                break

            # Take up to max_lines lines from the start of the file
            lines_to_take = sf.lines[:max_lines]
            code = "".join(text for _, text in lines_to_take)

            # Apply whitespace compression
            code = _compress_code(code)

            # Check budget
            if total_chars + len(code) > max_chars:
                # Take as many chars as remain in budget
                budget_left = max_chars - total_chars
                code = code[:budget_left]

            if not code.strip():
                continue

            end_line = lines_to_take[-1][0] if lines_to_take else sf.line_count
            snippets.append({
                "file_path":  sf.rel_path,
                "start_line": 1,
                "end_line":   end_line,
                "language":   sf.language,
                "code":       code,
            })
            total_chars += len(code)

        return snippets

    # ----------------------------------------------------------
    # INVESTIGATION SUMMARY  (SOC context for the prompt)
    # ----------------------------------------------------------

    def _summarise_investigation(
        self,
        investigation: Optional[dict],
        *,
        include_logs: bool = False,
    ) -> dict:
        """
        Return a slim summary of the SOC investigation for the audit prompt.
        Only includes fields Gemini should see.

        When include_logs is True (deep scan), raw logs are included
        so Gemini can correlate source code with observed traffic.
        """
        if not investigation:
            return {}

        summary: dict = {
            "id":             investigation.get("id"),
            "trigger_reasons": investigation.get("trigger_reasons", []),
            "trigger_score":   investigation.get("trigger_score", 0),
            "finding":         investigation.get("finding"),  # may be None
        }

        if include_logs:
            # Include raw logs for deep scan correlation
            logs = investigation.get("logs", [])
            summary["raw_logs"] = [
                {
                    "timestamp": log.get("timestamp"),
                    "source_ip": log.get("source_ip"),
                    "method":    log.get("method"),
                    "path":      log.get("path"),
                    "status":    log.get("status"),
                }
                for log in logs[:10]  # cap at 10 logs (was 20)
            ]

        return summary

    # ----------------------------------------------------------
    # AUDIT CONTEXT ASSEMBLY
    # ----------------------------------------------------------

    def _build_audit_context(
        self,
        audit_result: AuditResult,
        snippets: List[dict],
        deps: List[DependencyInfo],
        techs: List[str],
        knowledge_context: dict,
        soc_summary: dict,
    ) -> dict:
        """
        Assemble the flat dict consumed by GeminiClient.analyze_code_audit()
        and _build_audit_prompt().
        """
        return {
            "audit_id":         audit_result.audit_id,
            "investigation_id": audit_result.investigation_id,
            "technologies":     techs,
            "dependencies":     [d.model_dump() for d in deps],
            "source_snippets":  snippets,
            "knowledge_context": knowledge_context,
            "soc_context":      soc_summary,
        }
