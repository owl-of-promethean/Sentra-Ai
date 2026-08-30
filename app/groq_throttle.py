"""
Rolling TPM-aware request throttle for Groq LLM calls.

Tracks estimated token usage (input + output reservation) over a
rolling 60-second window — matching Groq's TPM window — and waits
until enough capacity is available before allowing the next request.

This prevents the "Used + Requested > 8000" error that occurs when
multiple requests accumulate inside the rolling window.

Algorithm:
  1.  Each request records ``(timestamp, input_tokens + output_tokens)``.
  2.  Before a new request, expired reservations (> 60 s old) are pruned.
  3.  Active reservations are summed.
  4.  If ``active + requested > BUDGET``, the throttle sleeps until the
      oldest reservation that would free enough capacity expires.
  5.  Requests are serialised through ``threading.Lock`` so two large
      LLM calls can never launch concurrently.

Design rules:
- threading.Lock (safe because audits run via run_in_executor).
- Does NOT block the FastAPI event loop (thread-based execution).
- Preserves existing timeout behaviour.
- No changes to the Groq provider model, API key, or configuration.
"""

import threading
import time


class GroqThrottle:
    """
    Rolling-window TPM rate-limiter for Groq.

    Each ``acquire()`` call reserves *input_tokens + output_tokens*
    in a rolling 60-second window.  When the next request would
    exceed the budget, the call blocks (``time.sleep``) until enough
    old reservations expire from the window.
    """

    # Groq hard limit: 8,000 tokens per minute (rolling window).
    GROQ_TPM_LIMIT = 8_000
    # Conservative budget — leave headroom so we never touch the wall.
    TPM_BUDGET = 7_500
    # Rolling-window length in seconds (matches Groq's 60-s window).
    WINDOW_SECONDS = 60.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # List of (timestamp, total_tokens_reserved) tuples.
        self._reservations: list[tuple[float, int]] = []

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def acquire(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """
        Block until the rolling-window TPM budget can accommodate
        *input_tokens + output_tokens*, then reserve that amount.

        Thread-safe: only one thread may compute + sleep + record
        at a time, so concurrent callers are serialised naturally.
        """
        total_tokens = input_tokens + output_tokens

        with self._lock:
            # -- 1. Purge reservations older than the window --------
            now = time.monotonic()
            cutoff = now - self.WINDOW_SECONDS
            self._reservations = [
                (ts, tok) for ts, tok in self._reservations if ts > cutoff
            ]

            # -- 2. Compute current active usage --------------------
            active = sum(tok for _, tok in self._reservations)

            # -- 3. Wait if adding this request exceeds the budget --
            if active + total_tokens > self.TPM_BUDGET:
                # How many tokens must expire before we fit?
                need_to_expire = active + total_tokens - self.TPM_BUDGET
                accumulated = 0
                wait_until = now
                for ts, tok in self._reservations:
                    accumulated += tok
                    if accumulated >= need_to_expire:
                        # Sleep until this reservation falls out of
                        # the 60-second window.
                        wait_until = ts + self.WINDOW_SECONDS
                        break

                wait_seconds = max(0.0, wait_until - time.monotonic())
                if wait_seconds > 0:
                    time.sleep(wait_seconds)

                    # Re-purge after waking.
                    now = time.monotonic()
                    cutoff = now - self.WINDOW_SECONDS
                    self._reservations = [
                        (ts, tok)
                        for ts, tok in self._reservations
                        if ts > cutoff
                    ]

            # -- 4. Record the new reservation ----------------------
            self._reservations.append((time.monotonic(), total_tokens))

    def reset(self) -> None:
        """Clear all reservations (useful in tests)."""
        with self._lock:
            self._reservations.clear()


# ==============================================================
# MODULE-LEVEL SINGLETON
# ==============================================================

_throttle: GroqThrottle | None = None


def get_groq_throttle() -> GroqThrottle:
    """Return the shared GroqThrottle singleton."""
    global _throttle
    if _throttle is None:
        _throttle = GroqThrottle()
    return _throttle
