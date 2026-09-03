"""
Orchestrator for Advanced AI [BETA] validation jobs.

Runs the full pipeline as an explicit state machine:

    queued -> preparing_sandbox -> crawling -> analyzing ->
    planning_tests -> validating -> evaluating -> completed

Any state can transition to failed (with cleanup) or cancelled.
Every transition is recorded in the job timeline and emitted as a
structured event. A failed AI call NEVER destroys the underlying
audit/investigation records — it only fails the job with a useful
error.

The orchestrator is fully synchronous; async callers run it through
run_in_executor (same pattern as the audit engine).
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from app.advanced_ai.attack_planner import (
    build_fallback_plan,
    sanitize_plan,
)
from app.advanced_ai.crawler import SandboxCrawler
from app.advanced_ai.evaluator import evaluate_fallback
from app.advanced_ai.events import log_event
from app.advanced_ai.gemini_bridge import evaluate_via_gemini, plan_via_gemini
from app.advanced_ai.sandbox import SandboxError, SandboxManager
from app.advanced_ai.schemas import (
    AdvancedAIJob,
    FindingSnapshot,
    ValidationPlan,
)
from app.advanced_ai.validator import ValidationExecutor


# ==============================================================
# JOB STORE  (in-memory, thread-safe; same pattern as _audits)
# ==============================================================

class JobStore:
    """Thread-safe in-memory store for Advanced AI jobs."""

    def __init__(self) -> None:
        self._jobs: Dict[str, AdvancedAIJob] = {}
        self._lock = threading.Lock()

    def add(self, job: AdvancedAIJob) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str) -> Optional[AdvancedAIJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> List[AdvancedAIJob]:
        with self._lock:
            jobs = list(self._jobs.values())
        # Newest first
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs

    def metrics(self) -> dict:
        """Real counts only — never fabricated statistics."""
        jobs = self.list()
        verdicts = {
            "VULNERABLE": 0,
            "MITIGATED": 0,
            "INCONCLUSIVE": 0,
        }
        for job in jobs:
            if job.status == "completed" and job.result:
                verdicts[job.result.verdict] = (
                    verdicts.get(job.result.verdict, 0) + 1
                )
        return {
            "total_jobs": len(jobs),
            "completed": sum(1 for j in jobs if j.status == "completed"),
            "failed": sum(1 for j in jobs if j.status == "failed"),
            "cancelled": sum(1 for j in jobs if j.status == "cancelled"),
            "running": sum(
                1 for j in jobs
                if j.status not in ("completed", "failed", "cancelled")
            ),
            "confirmed_vulnerable": verdicts["VULNERABLE"],
            "mitigated": verdicts["MITIGATED"],
            "inconclusive": verdicts["INCONCLUSIVE"],
        }


_job_store: Optional[JobStore] = None


def get_job_store() -> JobStore:
    """Return the shared JobStore instance."""
    global _job_store
    if _job_store is None:
        _job_store = JobStore()
    return _job_store


# ==============================================================
# CONTEXT
# ==============================================================

class JobContext:
    """
    Everything the orchestrator needs, resolved and authorized by the
    API layer BEFORE the job starts.
    """

    def __init__(
        self,
        app,
        finding: Optional[FindingSnapshot],
        investigation: Optional[dict] = None,
        use_gemini: bool = True,
    ) -> None:
        self.app = app                    # AuthorizedApp (trusted registry)
        self.finding = finding
        self.investigation = investigation or {}
        self.use_gemini = use_gemini


# ==============================================================
# ORCHESTRATOR
# ==============================================================

class Orchestrator:
    """
    Runs one Advanced AI job through the validation pipeline.

    All collaborators are injectable so tests can run fully offline
    (mock transports, gemini disabled).
    """

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        crawler: Optional[SandboxCrawler] = None,
        executor_factory=None,
    ) -> None:
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.crawler = crawler or SandboxCrawler()
        # executor_factory(base_url) -> ValidationExecutor
        self.executor_factory = executor_factory or (
            lambda base_url: ValidationExecutor(base_url)
        )

    # ----------------------------------------------------------
    # PUBLIC: run the pipeline
    # ----------------------------------------------------------

    def run(self, job: AdvancedAIJob, ctx: JobContext) -> AdvancedAIJob:
        """
        Execute the full pipeline synchronously.

        Mutates job in place and returns it. Never raises: every
        failure path ends in status='failed' with cleanup performed.
        """
        store = get_job_store()
        job_start = time.monotonic()
        _JOB_TIMEOUT_S = 120

        def _save() -> None:
            store.add(job)  # dict write — upsert semantics

        def _cancelled() -> bool:
            return job.cancel_requested

        def _timed_out() -> bool:
            return (time.monotonic() - job_start) > _JOB_TIMEOUT_S

        try:
            # ---- 1. SANDBOX ------------------------------------------
            if _cancelled():
                return self._finish_cancelled(job)
            job.transition("preparing_sandbox")
            _save()
            try:
                sandbox = self.sandbox_manager.create(ctx.app)
            except SandboxError as exc:
                return self._finish_failed(job, str(exc))
            job.sandbox = sandbox
            self.sandbox_manager.mark_running(sandbox)
            _save()

            # ---- 2. CRAWL --------------------------------------------
            if _cancelled():
                return self._finish_cancelled(job)
            job.transition("crawling")
            _save()
            log_event("crawl_started", job_id=job.job_id)
            try:
                seeds = self._approved_seed_paths(ctx.app)
                # Seed the finding's target endpoint for immediate discovery
                if ctx.finding and ctx.finding.target_endpoint:
                    if ctx.finding.target_endpoint not in seeds:
                        seeds = [ctx.finding.target_endpoint] + seeds
                endpoints = self.crawler.crawl(sandbox.base_url, seed_paths=seeds)
            except Exception as exc:
                return self._finish_failed(
                    job, f"Crawler failure: {exc}",
                )
            job.attack_surface = endpoints
            _save()

            # ---- 3. ANALYZE (existing audit/SOC evidence) ------------
            if _cancelled():
                return self._finish_cancelled(job)
            job.transition("analyzing")
            _save()
            finding = job.finding
            if finding is None:
                return self._finish_failed(
                    job, "No finding available to validate.",
                )
            log_event(
                "analysis_completed",
                job_id=job.job_id,
                finding_type=finding.vulnerability or finding.title,
                evidence_items=len(finding.evidence),
            )
            _save()

            # ---- 4. PLAN ---------------------------------------------
            if _cancelled():
                return self._finish_cancelled(job)
            if _timed_out():
                return self._finish_failed(
                    job, "Job exceeded overall time limit (120s).",
                )
            job.transition("planning_tests")
            _save()
            log_event("planning_started", job_id=job.job_id)
            elapsed = time.monotonic() - job_start
            remaining = max(0, _JOB_TIMEOUT_S - elapsed)
            plan = self._make_plan(job, ctx, endpoints, timeout_hint=remaining)
            job.plan = plan
            _save()
            if not plan.tests:
                # Nothing safe to run — complete as INCONCLUSIVE.
                from app.advanced_ai.schemas import ValidationResult
                job.evidence = []
                job.result = ValidationResult(
                    verdict="INCONCLUSIVE",
                    confidence=0.2,
                    reasoning=(
                        "No controlled validation strategy was available "
                        "for this finding: " + (plan.reasoning or "")
                    ),
                    source=plan.source,
                )
                return self._finish_completed(job)

            # ---- 5. VALIDATE -----------------------------------------
            if _cancelled():
                return self._finish_cancelled(job)
            job.transition("validating")
            _save()
            allowed = {e.endpoint for e in endpoints} | set(
                self._approved_seed_paths(ctx.app)
            )
            executor = self.executor_factory(sandbox.base_url)
            try:
                evidence = executor.execute(plan, allowed)
            except Exception as exc:
                return self._finish_failed(
                    job, f"Validation engine failure: {exc}",
                )
            job.evidence = evidence
            _save()

            # ---- 6. EVALUATE -----------------------------------------
            if _cancelled():
                return self._finish_cancelled(job)
            if _timed_out():
                return self._finish_failed(
                    job, "Job exceeded overall time limit (120s).",
                )
            job.transition("evaluating")
            _save()
            elapsed = time.monotonic() - job_start
            remaining = max(0, _JOB_TIMEOUT_S - elapsed)
            job.result = self._evaluate(job, ctx, plan, evidence, timeout_hint=remaining)
            _save()

            # ---- 7. COMPLETE -----------------------------------------
            return self._finish_completed(job)

        except Exception as exc:  # absolute safety net
            return self._finish_failed(job, f"Unexpected pipeline error: {exc}")

    # ----------------------------------------------------------
    # PHASE HELPERS
    # ----------------------------------------------------------

    def _make_plan(self, job, ctx, endpoints, timeout_hint: float = 0) -> ValidationPlan:
        """LLM-provider planning with deterministic fallback."""
        if ctx.use_gemini:
            soc_ctx = None
            if ctx.investigation:
                soc_ctx = {
                    "trigger_reasons": ctx.investigation.get("trigger_reasons", []),
                    "finding": ctx.investigation.get("finding"),
                }
            if ctx.finding and ctx.finding.target_endpoint:
                if soc_ctx is None:
                    soc_ctx = {}
                soc_ctx["target_endpoint"] = ctx.finding.target_endpoint
            gem_result = plan_via_gemini(
                job.finding, endpoints, soc_context=soc_ctx,
                timeout=min(timeout_hint, 30) if timeout_hint else 30,
            )
            if gem_result.get("success"):
                plan = sanitize_plan(gem_result["plan"], self._allowed_paths(ctx, endpoints))
                if plan.tests:
                    log_event(
                        "plan_generated",
                        job_id=job.job_id,
                        source=plan.source,
                        tests=len(plan.tests),
                    )
                    return plan
            log_event(
                "plan_fallback",
                job_id=job.job_id,
                reason=gem_result.get("error", "unknown"),
            )

        plan = build_fallback_plan(job.finding, endpoints)
        plan = sanitize_plan(plan, self._allowed_paths(ctx, endpoints))
        log_event(
            "plan_generated",
            job_id=job.job_id,
            source=plan.source,
            tests=len(plan.tests),
        )
        return plan

    def _evaluate(self, job, ctx, plan, evidence, timeout_hint: float = 0):
        """LLM-provider evaluation with deterministic fallback."""
        if ctx.use_gemini:
            gem_result = evaluate_via_gemini(
                job.finding, plan, evidence,
                timeout=min(timeout_hint, 30) if timeout_hint else 30,
            )
            if gem_result.get("success"):
                log_event(
                    "evaluation_completed",
                    job_id=job.job_id,
                    source=gem_result["result"].source,
                    verdict=gem_result["result"].verdict,
                )
                return gem_result["result"]
            log_event(
                "evaluation_fallback",
                job_id=job.job_id,
                reason=gem_result.get("error", "unknown"),
            )

        result = evaluate_fallback(plan, evidence)
        log_event(
            "evaluation_completed",
            job_id=job.job_id,
            source=result.source,
            verdict=result.verdict,
        )
        return result

    @staticmethod
    def _approved_seed_paths(app) -> List[str]:
        """Paths the registry explicitly approves for this target."""
        seeds: List[str] = []
        for scope in app.allowed_scopes:
            if scope.scope_id == "endpoint":
                seeds.extend(scope.paths)
        return seeds

    def _allowed_paths(self, ctx, endpoints) -> List[str]:
        return [e.endpoint for e in endpoints] + self._approved_seed_paths(ctx.app)

    # ----------------------------------------------------------
    # TERMINAL STATES  (always clean up the sandbox)
    # ----------------------------------------------------------

    def _finish_completed(self, job: AdvancedAIJob) -> AdvancedAIJob:
        job.transition("completed")
        job.completed_at = job.updated_at
        if job.sandbox:
            self.sandbox_manager.mark_completed(job.sandbox)
            self.sandbox_manager.destroy(job.sandbox)
        get_job_store().add(job)
        log_event(
            "advanced_ai_completed",
            job_id=job.job_id,
            verdict=job.result.verdict if job.result else None,
        )
        self._update_history(job)
        return job

    def _finish_failed(self, job: AdvancedAIJob, error: str) -> AdvancedAIJob:
        job.error = error
        job.transition("failed")
        job.completed_at = job.updated_at
        # Cleanup: always destroy any sandbox we created.
        if job.sandbox:
            self.sandbox_manager.destroy(job.sandbox)
        get_job_store().add(job)
        log_event("advanced_ai_failed", job_id=job.job_id, error=error)
        self._update_history(job)
        return job

    def _finish_cancelled(self, job: AdvancedAIJob) -> AdvancedAIJob:
        job.transition("cancelled")
        job.completed_at = job.updated_at
        if job.sandbox:
            self.sandbox_manager.destroy(job.sandbox)
        get_job_store().add(job)
        log_event("advanced_ai_cancelled", job_id=job.job_id)
        self._update_history(job)
        return job

    @staticmethod
    def _update_history(job: AdvancedAIJob) -> None:
        """Persist job outcome to the shared Sentra history store."""
        try:
            from app.history import get_history_store
            get_history_store().update_advanced_ai_entry(job)
        except Exception as exc:
            print(f"  [History] Failed to update Advanced AI entry: {exc}")
