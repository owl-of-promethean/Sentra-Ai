"""
Log Processing Module for Sentra AI.

Responsibilities:

    Incoming logs
          ↓
    10-second windows
          ↓
    Window processing
          ↓
    Generic investigation trigger
          ↓
    Investigation layer

This module does NOT identify SQL injection, XSS, brute force,
or any other specific attack.

Those decisions belong to the AI investigation layer.
"""

import json
import os
import threading
import uuid

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from app.audit_schemas import make_display_id
from app.retriever import retrieve_knowledge


class LogProcessor:
    """
    Handles log ingestion and 10-second processing windows.
    """

    def __init__(
        self,
        logs_directory: str = "data/logs",
        window_seconds: int = 10
    ):
        self.logs_directory = logs_directory
        self.window_seconds = window_seconds

        os.makedirs(self.logs_directory, exist_ok=True)

        # All logs currently held in memory.
        self._logs: List[dict] = []

        # Logs organized by 10-second window.
        self._window_logs: dict[str, List[dict]] = defaultdict(list)

        # Track processed windows to prevent duplicate investigations.
        self._processed_windows: set = set()

        # Store created investigations (in-memory).
        self._investigations: List[dict] = []

        # Protect shared memory because FastAPI may handle
        # multiple requests concurrently.
        self._lock = threading.Lock()

    # ==========================================================
    # LOG INGESTION
    # ==========================================================

    def ingest_log(self, log_data: dict) -> dict:
        """
        Add one log to the current processing window.
        """

        log_entry = {
            "log_id": str(uuid.uuid4()),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            **log_data
        }

        window_key = self._get_window_key()

        with self._lock:
            self._logs.append(log_entry)
            self._window_logs[window_key].append(log_entry)

        return log_entry

    # ==========================================================
    # WINDOW CALCULATION
    # ==========================================================

    def _get_window_start(self) -> datetime:
        """
        Return the start of the current 10-second window.

        Example:

        15:32:01 → 15:32:00
        15:32:07 → 15:32:00
        15:32:19 → 15:32:10
        """

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        window_start_second = (
            now.second // self.window_seconds
        ) * self.window_seconds

        return now.replace(
            second=window_start_second,
            microsecond=0
        )

    def _get_window_key(self) -> str:
        """Return the current window identifier."""

        return self._get_window_start().isoformat()

    # ==========================================================
    # WINDOW RETRIEVAL
    # ==========================================================

    def get_logs_for_window(
        self,
        window_start: datetime
    ) -> List[dict]:
        """
        Return logs belonging to a specific window.
        """

        key = window_start.isoformat()

        with self._lock:
            return self._window_logs.get(key, []).copy()

    def get_logs_for_current_window(self) -> List[dict]:
        """Return logs ingested within the last *window_seconds* seconds.

        Uses a sliding window based on each log's ``ingested_at``
        timestamp so that freshly ingested logs always appear in
        stats regardless of fixed-bucket boundary crossings.
        """

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)

        with self._lock:
            return [
                log for log in self._logs
                if datetime.fromisoformat(log["ingested_at"]) > cutoff
            ]

    def get_all_logs(self) -> List[dict]:
        """Return all logs currently stored in memory."""

        with self._lock:
            return self._logs.copy()

    # ==========================================================
    # WINDOW PROCESSING
    # ==========================================================

    def process_completed_window(self) -> dict:
        """
        Process the most recently completed 10-second window.

        This function does NOT determine the attack type.

        It only creates the processing result that will later
        feed the investigation trigger.
        """

        current_window = self._get_window_start()

        completed_window_start = (
            current_window -
            timedelta(seconds=self.window_seconds)
        )

        completed_key = completed_window_start.isoformat()

        with self._lock:
            logs = self._window_logs.get(
                completed_key,
                []
            ).copy()

        window_end = (
            completed_window_start +
            timedelta(seconds=self.window_seconds)
        )

        # Generic behavioral investigation trigger.
        #
        # We deliberately do NOT classify events as:
        # SQL injection
        # XSS
        # brute force
        # specific payloads
        #
        # Instead we check for generic behavioral signals:
        # - High request volume
        # - Multiple failures from same IP
        # - Rapid repeated requests
        # - Abnormal status code distribution
        # - Unusual HTTP methods
        #
        # Each signal adds to the trigger score.
        # Higher scores mean stronger suspicion.

        trigger_reasons = []
        trigger_score = 0

        if len(logs) == 0:
            should_investigate = False
        else:
            # Signal 1: High request volume (threshold: >15 requests/10s)
            if len(logs) > 15:
                trigger_reasons.append("high request volume")
                trigger_score += 2

            # Signal 2: Multiple failures from same source IP
            ip_failures = defaultdict(int)
            for log in logs:
                status_code = log.get("status", 200)
                if isinstance(status_code, int) and status_code >= 400:
                    ip = log.get("source_ip", "unknown")
                    ip_failures[ip] += 1

            for ip, count in ip_failures.items():
                if count >= 3:
                    trigger_reasons.append(
                        f"multiple failures from {ip}"
                    )
                    trigger_score += 2
                    break  # Only add once

            # Signal 3: Unusually high error rate (>50% errors)
            total_errors = sum(
                1 for log in logs
                if isinstance(log.get("status", 200), int) and log.get("status", 200) >= 400
            )
            error_rate = total_errors / len(logs) if logs else 0

            if error_rate > 0.5:
                trigger_reasons.append("high error rate")
                trigger_score += 1

            # Signal 4: Many different paths accessed rapidly
            unique_paths = len(set(
                log.get("path", "") for log in logs
            ))

            if unique_paths > len(logs) * 0.8 and len(logs) >= 5:
                trigger_reasons.append("rapid path scanning")
                trigger_score += 2

            # Signal 5: Unusual HTTP methods
            unusual_methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            unusual_count = sum(
                1 for log in logs
                if log.get("method", "GET") in unusual_methods
            )

            if unusual_count > 0 and unusual_count >= len(logs) * 0.5:
                trigger_reasons.append("unusual HTTP methods")
                trigger_score += 1

            # Decision: Investigate if any strong signals detected
            should_investigate = trigger_score >= 2 or len(trigger_reasons) >= 2

        return {
            "window_start": completed_window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "log_count": len(logs),
            "logs": logs,
            "status": "processed",
            "should_investigate": should_investigate,
            "trigger_score": trigger_score,
            "trigger_reasons": trigger_reasons
        }

    def process_windows_summary(self) -> dict:
        """
        Return a lightweight summary of the latest completed window.

        Used for console output and testing.
        """

        result = self.process_completed_window()

        return {
            "window_start": result["window_start"],
            "window_end": result["window_end"],
            "log_count": result["log_count"],
            "status": result["status"],
            "should_investigate": result["should_investigate"],
            "trigger_score": result["trigger_score"],
            "trigger_reasons": result["trigger_reasons"]
        }

    # ==========================================================
    # MEMORY MANAGEMENT
    # ==========================================================

    def clear_old_logs(
        self,
        max_age_seconds: int = 3600
    ) -> None:
        """
        Remove old logs from memory.
        """

        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(seconds=max_age_seconds)
        )

        with self._lock:

            self._logs = [
                log
                for log in self._logs
                if datetime.fromisoformat(
                    log["ingested_at"]
                ) > cutoff
            ]

            old_windows = []

            for key in self._window_logs.keys():

                try:
                    window_time = datetime.fromisoformat(key)
                    # Window keys are naive; compare with naive cutoff.
                    if window_time < cutoff.replace(tzinfo=None):
                        old_windows.append(key)

                except ValueError:
                    continue

            for key in old_windows:
                del self._window_logs[key]

    # ==========================================================
    # FILE OPERATIONS
    # ==========================================================

    def load_logs(
        self,
        filename: str
    ) -> List[dict]:
        """Load logs from a JSON file."""

        filepath = os.path.join(
            self.logs_directory,
            filename
        )

        if not os.path.exists(filepath):
            raise FileNotFoundError(
                f"Log file not found: {filepath}"
            )

        with open(filepath, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict) and "logs" in data:
            return data["logs"]

        return [data]

    def save_logs(
        self,
        logs: List[dict],
        filename: str
    ) -> None:
        """Save logs to a JSON file."""

        filepath = os.path.join(
            self.logs_directory,
            filename
        )

        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(
                logs,
                file,
                indent=2,
                default=str
            )

    # ==========================================================
    # GENERIC GROUPING HELPERS
    # ==========================================================

    def group_logs_by_source_ip(
        self,
        logs: List[dict]
    ) -> dict[str, List[dict]]:
        """Group logs by source IP."""

        grouped = defaultdict(list)

        for log in logs:
            ip = log.get(
                "source_ip",
                "unknown"
            )

            grouped[ip].append(log)

        return dict(grouped)

    def group_logs_by_time_window(
        self,
        logs: List[dict],
        window_minutes: int = 5
    ) -> List[List[dict]]:
        """
        Group arbitrary logs into time windows.

        This helper remains separate from the main
        10-second processing mechanism.
        """

        if not logs:
            return []

        parsed_logs = []

        for log in logs:

            timestamp = log.get("timestamp")

            if not timestamp:
                continue

            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

            except (ValueError, AttributeError):
                continue

            parsed_logs.append(
                (timestamp, log)
            )

        if not parsed_logs:
            return []

        parsed_logs.sort(
            key=lambda item: item[0]
        )

        windows = []

        current_window = []
        window_start = None

        for timestamp, log in parsed_logs:

            if window_start is None:

                window_start = timestamp
                current_window = [log]

                continue

            elapsed = (
                timestamp - window_start
            ).total_seconds()

            if elapsed <= window_minutes * 60:

                current_window.append(log)

            else:

                windows.append(
                    current_window
                )

                current_window = [log]
                window_start = timestamp

        if current_window:
            windows.append(current_window)

        return windows

    # ==========================================================
    # FEATURE CALCULATION
    # ==========================================================

    def calculate_window_features(self, logs: List[dict]) -> dict:
        """
        Calculate security-relevant features from a window of logs.

        This function provides evidence for future AI analysis WITHOUT
        attempting to classify attacks.

        Args:
            logs: List of log entries from a window.

        Returns:
            Dictionary containing calculated features.
        """

        if not logs:
            return {
                "total_requests": 0,
                "unique_ips": 0,
                "requests_per_ip": {},
                "unique_paths": 0,
                "error_rate": 0.0,
                "status_code_counts": {},
                "http_method_counts": {},
                "requests_per_path": {},
                "unique_user_agents": 0,
                "user_agent_counts": {},
                "time_span_seconds": 0.0,
                "requests_per_second": 0.0
            }

        # Collect data safely with defaults
        ips = []
        paths = []
        statuses = []
        methods = []
        user_agents = []
        timestamps = []

        for log in logs:
            try:
                ip = log.get("source_ip", None)
                if ip is not None:
                    ips.append(ip)

                path = log.get("path", None)
                if path is not None:
                    paths.append(path)

                status = log.get("status", None)
                if status is not None:
                    statuses.append(str(status))

                method = log.get("method", None)
                if method is not None:
                    methods.append(method)

                ua = log.get("user_agent", None)
                if ua is not None:
                    user_agents.append(ua)

                timestamp = log.get("timestamp", None)
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(
                            timestamp.replace("Z", "+00:00")
                        )
                        timestamps.append(dt)
                    except (ValueError, AttributeError):
                        pass

            except Exception:
                continue  # Skip malformed logs gracefully

        # Count frequencies safely
        ip_counts = {}
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        path_counts = {}
        for path in paths:
            path_counts[path] = path_counts.get(path, 0) + 1

        status_counts = {}
        for status in statuses:
            status_counts[status] = status_counts.get(status, 0) + 1

        method_counts = {}
        for method in methods:
            method_counts[method] = method_counts.get(method, 0) + 1

        ua_counts = {}
        for ua in user_agents:
            ua_counts[ua] = ua_counts.get(ua, 0) + 1

        # Calculate derived metrics
        total_requests = len(logs)
        unique_ips = len(set(ips))
        unique_paths = len(set(paths))
        unique_uas = len(set(user_agents))

        errors_count = sum(
            1 for s in statuses if int(s) >= 400
        )
        error_rate = errors_count / total_requests if total_requests > 0 else 0.0

        time_span = 0.0
        if len(timestamps) >= 2:
            sorted_ts = sorted(timestamps)
            time_span = (
                sorted_ts[-1] - sorted_ts[0]
            ).total_seconds()

        requests_per_second = (
            total_requests / time_span
            if time_span > 0 else float(total_requests)
        )

        return {
            "total_requests": total_requests,
            "unique_ips": unique_ips,
            "requests_per_ip": ip_counts,
            "unique_paths": unique_paths,
            "error_rate": error_rate,
            "status_code_counts": status_counts,
            "http_method_counts": method_counts,
            "requests_per_path": path_counts,
            "unique_user_agents": unique_uas,
            "user_agent_counts": ua_counts,
            "time_span_seconds": round(time_span, 3),
            "requests_per_second": round(requests_per_second, 3)
        }

    # ==========================================================
    # INVESTIGATION HANDOFF
    # ==========================================================

    def handle_investigation_trigger(self, result: dict) -> Optional[dict]:
        """
        Create an investigation object when a window triggers.

        Args:
            result: The result dictionary from process_completed_window().

        Returns:
            Investigation object if triggered, None otherwise.
        
        This method reuses the existing trigger result.
        It does NOT duplicate or rewrite the trigger detection logic.
        """
        
        # Check if this window has already been processed (prevent duplicates).
        window_start = result["window_start"]
        
        with self._lock:
            if window_start in self._processed_windows:
                return None  # Already handled this window
            
            # Mark this window as processed.
            self._processed_windows.add(window_start)
        
        # Create investigation only when triggered.
        if not result.get("should_investigate", False):
            return None
        
        # Calculate features from logs.
        features = self.calculate_window_features(result["logs"])
        
        # Build investigation object.
        inv_id = str(uuid.uuid4())
        investigation = {
            "id": inv_id,
            "display_id": make_display_id(inv_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "window_start": result["window_start"],
            "window_end": result["window_end"],
            "log_count": result["log_count"],
            "trigger_score": result["trigger_score"],
            "trigger_reasons": result["trigger_reasons"],
            "logs": result["logs"],  # Include actual logs from window
            "status": "pending",
            "features": features  # Feature calculations for AI analysis
        }

        # Retrieve relevant cybersecurity knowledge for this investigation.
        #
        # The retriever provides contextual knowledge only.
        # It does NOT classify attacks — that is Gemini's responsibility.
        # If retrieval fails for any reason the investigation is preserved.
        try:
            knowledge_context = retrieve_knowledge(
                result["trigger_reasons"]
            )
        except Exception:
            # A retrieval error must never prevent investigation creation.
            knowledge_context = {
                "status": "error",
                "sources": [],
                "context": "",
            }

        investigation["knowledge_context"] = knowledge_context

        # Store investigation in memory.
        with self._lock:
            self._investigations.append(investigation)

        return investigation

    def get_all_investigations(self) -> List[dict]:
        """
        Return all investigations currently stored in memory.
        
        Useful for debugging and testing.
        """
        with self._lock:
            return self._investigations.copy()

    def retrieve_investigation_logs(self, investigation_id: str) -> Optional[List[dict]]:
        """
        Retrieve logs for a specific investigation by ID.
        
        Args:
            investigation_id: The investigation identifier.
        
        Returns:
            List of logs, or None if investigation not found.
        """
        with self._lock:
            for investigation in self._investigations:
                if investigation["id"] == investigation_id:
                    return investigation["logs"]
            return None

    # ==========================================================
    # FUTURE INVESTIGATION WINDOW
    # ==========================================================

    def prepare_investigation_window(
        self,
        logs: List[dict],
        trigger_reason: str,
        window_id: Optional[str] = None
    ) -> dict:
        """
        Prepare logs for the future investigation layer.

        No AI is called here.
        """

        return {
            "id": (
                window_id
                or str(uuid.uuid4())
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "trigger_reason": trigger_reason,
            "logs": logs,
            "status": "pending"
        }


# ==============================================================
# GLOBAL PROCESSOR
# ==============================================================

_log_processor: Optional[LogProcessor] = None


def get_log_processor() -> LogProcessor:
    """Return the shared LogProcessor instance."""

    global _log_processor

    if _log_processor is None:
        _log_processor = LogProcessor(
            window_seconds=10
        )

    return _log_processor


def load_logs(
    filename: str
) -> List[dict]:
    """Convenience function for loading logs."""

    return get_log_processor().load_logs(
        filename
    )


def group_logs_by_source_ip(
    logs: List[dict]
) -> dict:
    """Convenience function for grouping logs."""

    return get_log_processor().group_logs_by_source_ip(
        logs
    )