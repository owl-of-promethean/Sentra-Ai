"""
Structured event logging for the Advanced AI [BETA] pipeline.

Events are emitted as single JSON lines prefixed with [ADVANCED-AI]
so they integrate with Sentra's existing console/logging output.

Event names follow the conventions:
    sandbox_created, sandbox_failed, sandbox_destroyed,
    crawl_started, crawl_completed,
    planning_started, plan_generated, plan_fallback,
    validation_started, validation_completed,
    evaluation_completed, evaluation_fallback,
    advanced_ai_completed, advanced_ai_failed, advanced_ai_cancelled
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def log_event(event_type: str, **fields) -> None:
    """
    Emit one structured Advanced AI event line.

    Args:
        event_type: Stable machine-readable event name.
        **fields:   Arbitrary JSON-serializable context fields.
    """
    payload = {
        "event": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(fields)
    try:
        line = json.dumps(payload, default=str)
    except Exception:
        line = json.dumps({"event": event_type, "error": "unserializable fields"})
    print(f"  [ADVANCED-AI] {line}", flush=True)
