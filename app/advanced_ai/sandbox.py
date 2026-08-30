"""
Sandbox lifecycle for Advanced AI [BETA].

The sandbox represents an isolated instance of the authorized demo
target that Advanced AI operates against — never an arbitrary
client-supplied URL.

For the hackathon prototype the sandbox is a logical isolation record
bound to the locally controlled target instance resolved from the
trusted application registry. Creation performs a real reachability
probe against the sandbox base URL; a sandbox that cannot be reached
is marked failed so the job fails fast with a useful error.

Lifecycle:
    CREATE -> READY -> RUN TESTS -> COLLECT EVIDENCE -> DESTROY/CLEANUP

No Docker/Kubernetes is introduced — the simplest reliable isolation
for the local demo is a dedicated process already under our control.
"""

from __future__ import annotations

from typing import Optional

import httpx

from app.advanced_ai.events import log_event
from app.advanced_ai.schemas import SandboxRecord


class SandboxError(Exception):
    """Raised when a sandbox cannot be created or prepared."""


class SandboxManager:
    """
    Creates and destroys validation sandboxes for authorized targets.

    The transport argument allows tests to inject an httpx.MockTransport
    so no real network is required.
    """

    def __init__(self, timeout: float = 5.0, transport=None) -> None:
        self.timeout = timeout
        self.transport = transport

    # ----------------------------------------------------------
    # CREATE
    # ----------------------------------------------------------

    def create(self, app) -> SandboxRecord:
        """
        Create a sandbox for an authorized application.

        Args:
            app: AuthorizedApp that has already passed
                 get_advanced_ai_target() checks (active,
                 advanced_ai_approved, has internal base_url).

        Returns:
            SandboxRecord with status='ready'.

        Raises:
            SandboxError: if the app is not approved for Advanced AI
                          or the sandbox instance is unreachable.
        """
        # Defense in depth — re-check approval even though callers
        # are expected to have resolved the target via the registry.
        if not getattr(app, "advanced_ai_approved", False) or not app.base_url:
            raise SandboxError(
                f"Application '{getattr(app, 'app_id', '?')}' is not approved "
                "for Advanced AI validation."
            )

        sandbox = SandboxRecord(
            target_id=app.app_id,
            target_name=app.name,
            status="creating",
            base_url=app.base_url.rstrip("/"),
            source_reference=f"registry:{app.app_id}",
        )

        # Real reachability probe — the sandbox must actually respond.
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self.transport,
                follow_redirects=True,
            ) as client:
                probe = client.get(sandbox.base_url + "/")
        except Exception as exc:
            sandbox.status = "failed"
            log_event(
                "sandbox_failed",
                sandbox_id=sandbox.sandbox_id,
                target_id=app.app_id,
                error=f"probe failed: {exc}",
            )
            raise SandboxError(
                f"Sandbox for '{app.name}' is unreachable at the registry "
                f"base URL ({exc}). Is the demo target running?"
            ) from exc

        if probe.status_code >= 500:
            sandbox.status = "failed"
            log_event(
                "sandbox_failed",
                sandbox_id=sandbox.sandbox_id,
                target_id=app.app_id,
                status=probe.status_code,
            )
            raise SandboxError(
                f"Sandbox probe returned HTTP {probe.status_code} — "
                "target instance is unhealthy."
            )

        sandbox.status = "ready"
        log_event(
            "sandbox_created",
            sandbox_id=sandbox.sandbox_id,
            target_id=app.app_id,
            probe_status=probe.status_code,
        )
        return sandbox

    # ----------------------------------------------------------
    # MARK RUNNING / COMPLETE
    # ----------------------------------------------------------

    def mark_running(self, sandbox: SandboxRecord) -> None:
        sandbox.status = "running"

    def mark_completed(self, sandbox: SandboxRecord) -> None:
        sandbox.status = "completed"

    # ----------------------------------------------------------
    # DESTROY / CLEANUP
    # ----------------------------------------------------------

    def destroy(self, sandbox: Optional[SandboxRecord]) -> None:
        """
        Tear down the sandbox record.

        For the prototype the sandbox is a logical record bound to a
        shared local demo instance, so destroy marks the record as
        destroyed. A container-based implementation would stop/remove
        the container here. Never raises.
        """
        if sandbox is None:
            return
        if sandbox.status == "destroyed":
            return
        sandbox.status = "destroyed"
        log_event(
            "sandbox_destroyed",
            sandbox_id=sandbox.sandbox_id,
            target_id=sandbox.target_id,
        )
