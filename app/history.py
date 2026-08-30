"""
Local history store for SOC-AI.

Persists both SOC investigations and audit records to a single JSON
file on disk so history survives a FastAPI process restart.

Design rules:
- One flat JSON list on disk; newest first when returned.
- Reads the whole file on every append (safe for prototype scale).
- Search is a simple case-insensitive substring match across indexed fields.
- Thread-safe via a threading.Lock (same pattern as LogProcessor).
- All internal_ids remain full UUIDs in storage.
- display_id is stored alongside but is purely presentational.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Optional

from app.audit_schemas import AuditResult, HistoryEntry, make_display_id


# ==============================================================
# DEFAULTS
# ==============================================================

_DEFAULT_HISTORY_FILE = "data/history.json"


# ==============================================================
# HISTORY STORE
# ==============================================================


class HistoryStore:
    """
    Append-only history store backed by a local JSON file.

    History entries are kept in insertion order in the file but are
    returned newest-first by the public API so the frontend doesn't
    need to reverse them.
    """

    def __init__(self, history_file: str = _DEFAULT_HISTORY_FILE) -> None:
        self.history_file = history_file
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(history_file), exist_ok=True)
        # Initialise file if it does not exist.
        if not os.path.exists(history_file):
            self._write([])

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def add_soc_entry(self, investigation: dict) -> HistoryEntry:
        """
        Record a SOC investigation in history.

        Called immediately after handle_investigation_trigger() creates
        a new investigation dict.  The finding/severity fields may not
        be populated yet (status='pending'); the entry is updated in
        place when Gemini finishes via update_soc_entry().

        Args:
            investigation: The full investigation dict from LogProcessor.

        Returns:
            The HistoryEntry that was persisted.
        """
        inv_id = investigation["id"]
        display_id = investigation.get("display_id") or make_display_id(inv_id)

        # Extract finding fields if Gemini has already returned
        # (won't happen at creation time, but defensive).
        finding = investigation.get("finding") or {}
        severity = finding.get("severity") if isinstance(finding, dict) else None
        activity_type = finding.get("activity_type") if isinstance(finding, dict) else None
        summary = finding.get("summary") if isinstance(finding, dict) else None

        entry = HistoryEntry(
            entry_type="soc",
            internal_id=inv_id,
            display_id=display_id,
            activity_type=activity_type,
            trigger_reasons=investigation.get("trigger_reasons", []),
            severity=severity,
            status=investigation.get("status", "pending"),
            summary=summary,
            timestamp=datetime.fromisoformat(
                investigation.get("created_at",
                                  datetime.now(timezone.utc).isoformat())
            ),
        )

        self._append(entry)
        return entry

    def update_soc_entry(self, investigation: dict) -> None:
        """
        Update an existing SOC history entry after Gemini analysis completes.

        Updates severity, activity_type, summary, and status in-place
        within the persisted list.

        Args:
            investigation: The investigation dict after analysis (status='analyzed').
        """
        inv_id = investigation["id"]
        finding = investigation.get("finding") or {}
        if not isinstance(finding, dict):
            return  # Nothing useful to update

        updates = {
            "status":        investigation.get("status", "analyzed"),
            "severity":      finding.get("severity"),
            "activity_type": finding.get("activity_type"),
            "summary":       finding.get("summary"),
        }

        self._update_entry(internal_id=inv_id, entry_type="soc", updates=updates)

    def add_audit_entry(self, audit: AuditResult) -> HistoryEntry:
        """
        Record an audit run in history.

        Args:
            audit: The AuditResult object.

        Returns:
            The HistoryEntry that was persisted.
        """
        entry = HistoryEntry(
            entry_type="audit",
            internal_id=audit.audit_id,
            display_id=audit.display_id,
            severity=None,  # Populated in Phase 2+ when findings arrive
            status=audit.status,
            summary=None,
            timestamp=audit.created_at,
            investigation_id=audit.investigation_id,
            investigation_display_id=audit.investigation_display_id,
        )

        self._append(entry)
        return entry

    def update_audit_entry(self, audit: AuditResult) -> None:
        """
        Update an existing audit history entry (e.g. status changed to complete).

        Args:
            audit: The updated AuditResult.
        """
        updates = {
            "status": audit.status,
            "error":  audit.error,
        }
        # severity/summary will be updated by Phase 2+ when findings are present.
        if audit.findings:
            severities = [
                f.severity for f in audit.findings if f.severity
            ]
            if severities:
                # Report the highest severity found.
                _order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                updates["severity"] = max(severities, key=lambda s: _order.get(s, 0))

        self._update_entry(
            internal_id=audit.audit_id,
            entry_type="audit",
            updates=updates,
        )

    def add_advanced_ai_entry(self, job) -> HistoryEntry:
        """
        Record an Advanced AI [BETA] validation job in history.

        Args:
            job: An app.advanced_ai.schemas.AdvancedAIJob instance.

        Returns:
            The HistoryEntry that was persisted.
        """
        finding = job.finding
        entry = HistoryEntry(
            entry_type="advanced_ai",
            internal_id=job.job_id,
            display_id=job.display_id,
            activity_type=finding.title if finding else None,
            severity=finding.severity if finding else None,
            status=job.status,
            summary=None,
            timestamp=job.created_at,
            investigation_id=job.investigation_id,
            investigation_display_id=job.investigation_display_id,
        )

        self._append(entry)
        return entry

    def update_advanced_ai_entry(self, job) -> None:
        """
        Update an existing Advanced AI history entry when the job
        reaches a terminal state (completed / failed / cancelled).

        Args:
            job: The updated AdvancedAIJob instance.
        """
        result = job.result
        updates = {"status": job.status}
        if result is not None:
            updates["summary"] = (
                f"Verdict: {result.verdict} "
                f"(confidence {round(result.confidence * 100)}%)"
            )
        elif job.error:
            updates["summary"] = f"Job failed: {job.error}"
        self._update_entry(
            internal_id=job.job_id,
            entry_type="advanced_ai",
            updates=updates,
        )

    def all_entries(self) -> List[dict]:
        """
        Return all history entries as raw dicts, newest first.
        """
        raw = self._read()
        return list(reversed(raw))

    def search(self, query: str) -> List[dict]:
        """
        Case-insensitive substring search across the indexed fields of
        every history entry.

        Searchable fields:
            internal_id, display_id, entry_type, status, severity,
            activity_type, summary, trigger_reasons (joined),
            investigation_id, investigation_display_id

        Returns entries newest-first that contain the query string in
        at least one of the above fields.

        Args:
            query: The search string.  Whitespace is not stripped so
                   callers can search for multi-word phrases.

        Returns:
            Filtered list of matching entries (newest first).
        """
        if not query:
            return self.all_entries()

        q = query.lower()
        results = []

        for entry in self.all_entries():  # already newest-first
            if self._entry_matches(entry, q):
                results.append(entry)

        return results

    # ----------------------------------------------------------
    # INTERNAL HELPERS
    # ----------------------------------------------------------

    def _entry_matches(self, entry: dict, q: str) -> bool:
        """Return True if the lowercase query appears in any searchable field."""
        searchable = [
            entry.get("internal_id", ""),
            entry.get("display_id", ""),
            entry.get("entry_type", ""),
            entry.get("status", ""),
            entry.get("severity", "") or "",
            entry.get("activity_type", "") or "",
            entry.get("summary", "") or "",
            entry.get("investigation_id", "") or "",
            entry.get("investigation_display_id", "") or "",
            # Join list fields so "brute force" in trigger_reasons still matches
            " ".join(entry.get("trigger_reasons", []) or []),
        ]
        return any(q in field.lower() for field in searchable)

    def _append(self, entry: HistoryEntry) -> None:
        """Persist a new entry to the JSON file (thread-safe)."""
        with self._lock:
            entries = self._read_unsafe()
            entries.append(entry.model_dump(mode="json"))
            self._write_unsafe(entries)

    def _update_entry(
        self,
        internal_id: str,
        entry_type: str,
        updates: dict,
    ) -> None:
        """Update fields on an existing entry identified by internal_id + entry_type."""
        with self._lock:
            entries = self._read_unsafe()
            for e in entries:
                if e.get("internal_id") == internal_id and e.get("entry_type") == entry_type:
                    for key, value in updates.items():
                        if value is not None:
                            e[key] = value
                    break
            self._write_unsafe(entries)

    def _read(self) -> List[dict]:
        """Thread-safe read of the history file."""
        with self._lock:
            return self._read_unsafe()

    def _read_unsafe(self) -> List[dict]:
        """Read the history file WITHOUT acquiring the lock (caller must hold it)."""
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _write(self, entries: List[dict]) -> None:
        """Thread-safe write of the full entries list."""
        with self._lock:
            self._write_unsafe(entries)

    def _write_unsafe(self, entries: List[dict]) -> None:
        """Write the full entries list WITHOUT acquiring the lock (caller must hold it)."""
        with open(self.history_file, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, default=str)


# ==============================================================
# MODULE-LEVEL SINGLETON
# ==============================================================

_history_store: Optional[HistoryStore] = None


def get_history_store() -> HistoryStore:
    """Return the shared HistoryStore instance."""
    global _history_store
    if _history_store is None:
        _history_store = HistoryStore()
    return _history_store
