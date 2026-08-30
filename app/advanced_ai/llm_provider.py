"""
LLM provider abstraction for Advanced AI [BETA] and Copilot.

Groq is the single LLM backend.  All AI reasoning flows through
get_llm_provider() → GroqProvider, which talks to the Groq
OpenAI-compatible Chat Completions API:

    https://api.groq.com/openai/v1
    openai/gpt-oss-20b

Every provider call returns the same envelope:

    {"success": True,  "text": <raw model output>}
    {"success": False, "error": <useful reason>}

so any failure (API/HTTP error, 429 rate limit, timeout, empty or
malformed response) degrades to the deterministic fallback planner /
evaluator exactly as before.  A provider error NEVER crashes a job.
"""

from __future__ import annotations

import logging
import os
import re

from app.config import Config

logger = logging.getLogger(__name__)


class LLMProviderError(Exception):
    """Raised when the LLM provider cannot be initialised."""


def _extract_json(raw_text: str) -> str:
    """
    Extract the first JSON object from a model's response text.

    Mirrors app.llm._extract_json: strips markdown code fences and
    otherwise falls back to the first {...} block, letting json.loads
    raise a clear error on truly malformed output.
    """
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if fenced:
        return fenced.group(1)

    brace_start = raw_text.find("{")
    brace_end = raw_text.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        return raw_text[brace_start : brace_end + 1]

    return raw_text  # Return as-is and let json.loads raise


def _diag_response_metadata(
    response,
    choice=None,
    message=None,
    content=None,
) -> str:
    """
    Build a safe, non-sensitive diagnostic string for an empty or
    unexpected Groq response.

    NEVER logs: API keys, auth headers, full prompts, source code,
    investigation logs, or sensitive response contents.

    Logs ONLY:
    * response object type
    * choices count
    * finish_reason (if choice provided)
    * whether message.content is None / empty / present
    * whether message has non-standard structured fields (names only)
    """
    parts: list[str] = []

    # Response object type
    parts.append(f"response_type={type(response).__name__}")

    # Choices count
    choices = getattr(response, "choices", None)
    if choices is None:
        parts.append("choices=None")
    else:
        parts.append(f"choices_count={len(choices)}")

    # Choice-level metadata
    if choice is not None:
        finish_reason = getattr(choice, "finish_reason", None)
        parts.append(f"finish_reason={finish_reason!r}")

        # Message-level metadata
        if message is not None:
            # content state: None / empty / whitespace / present
            if content is None:
                parts.append("content=None")
            elif isinstance(content, str) and content == "":
                parts.append("content=''")
            elif isinstance(content, str) and not content.strip():
                parts.append(f"content=whitespace(len={len(content)})")
            else:
                parts.append(f"content=present(len={len(str(content))})")

            # Check for non-standard structured fields on the message
            # (e.g. refusal, tool_calls, function_call).  Names only,
            # never values.
            standard_fields = {"role", "content"}
            extra_fields = [
                attr for attr in dir(message)
                if not attr.startswith("_")
                and attr not in standard_fields
                and not callable(getattr(message, attr, None))
            ]
            if extra_fields:
                parts.append(f"extra_message_fields={extra_fields}")
        else:
            parts.append("message=None")

    return " | ".join(parts)


# ==============================================================
# GROQ PROVIDER  (OpenAI-compatible Chat Completions)
# ==============================================================

class GroqProvider:
    """
    Groq path using the OpenAI Python client.

    Configuration (environment / .env):
        GROQ_API_KEY   — required
        GROQ_BASE_URL  — default https://api.groq.com/openai/v1
        GROQ_MODEL     — default openai/gpt-oss-20b
    """

    name = "groq"
    display_name = "Groq"

    # Conservative sampling for structured security JSON: deterministic-
    # leaning generation with ample room for plan/verdict payloads.
    temperature = 0.2
    top_p = 0.95
    max_tokens = 4096

    def __init__(self) -> None:
        api_key = os.getenv("GROQ_API_KEY") or Config.GROQ_API_KEY
        if not api_key:
            raise LLMProviderError(
                "GROQ_API_KEY is not set. "
                "Add it to the environment or .env file."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMProviderError(
                "The 'openai' package is required for Groq "
                f"(pip install openai): {exc}"
            ) from exc

        self.model = os.getenv("GROQ_MODEL") or Config.GROQ_MODEL
        # max_retries=0 keeps the per-request timeout a hard bound so the
        # existing Advanced AI planner/job timeout budget is respected.
        self._client = OpenAI(
            base_url=os.getenv("GROQ_BASE_URL") or Config.GROQ_BASE_URL,
            api_key=api_key,
            max_retries=0,
        )

    def generate(
        self,
        prompt: str,
        timeout: float = 30.0,
        max_tokens: int | None = None,
    ) -> dict:
        """
        Generate a completion via Groq.

        Args:
            prompt:     The user-message prompt.
            timeout:    Per-request timeout in seconds.
            max_tokens: Maximum output tokens for this request.  When
                        None (default), uses the class-level
                        ``self.max_tokens`` (4,096).
        """
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                top_p=self.top_p,
                max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
                timeout=timeout,
                stream=False,
            )
        except Exception as exc:
            # Surfaces the real provider error (429 rate limit, timeout,
            # HTTP/API failure) through the existing Advanced AI fallback
            # mechanism instead of crashing.
            return {
                "success": False,
                "error": f"Groq API error ({type(exc).__name__}): {exc}",
            }

        # ----------------------------------------------------------
        # Defensive shape validation — diagnostic empty-response cases.
        # Each branch logs ONLY non-sensitive metadata and returns a
        # distinct error string so the caller (and our test suite) can
        # tell which shape Groq actually returned.
        # ----------------------------------------------------------
        choices = getattr(response, "choices", None) or []

        # Case 1: choices=[]  (API returned zero completions)
        if not choices:
            diag = _diag_response_metadata(response)
            logger.warning("Groq empty response [no_choices]: %s", diag)
            return {
                "success": False,
                "error": f"Groq returned no choices. {diag}",
            }

        choice = choices[0]
        message = getattr(choice, "message", None)
        finish_reason = getattr(choice, "finish_reason", None)
        content = getattr(message, "content", None) if message else None

        # Case 5: refusal / content-filter  (finish_reason == "content_filter")
        if finish_reason in ("content_filter", "refusal"):
            diag = _diag_response_metadata(response, choice, message, content)
            logger.warning("Groq empty response [content_filter]: %s", diag)
            return {
                "success": False,
                "error": (
                    f"Groq response blocked by content filter "
                    f"(finish_reason={finish_reason!r}). {diag}"
                ),
            }

        # Case 2: message.content is None
        if content is None:
            diag = _diag_response_metadata(response, choice, message, content)
            logger.warning("Groq empty response [content_none]: %s", diag)
            return {
                "success": False,
                "error": (
                    f"Groq message.content is None "
                    f"(finish_reason={finish_reason!r}). {diag}"
                ),
            }

        # Case 3: message.content == ""  (empty string)
        if not str(content).strip():
            diag = _diag_response_metadata(response, choice, message, content)
            logger.warning("Groq empty response [content_empty]: %s", diag)
            return {
                "success": False,
                "error": (
                    f"Groq message.content is empty string "
                    f"(finish_reason={finish_reason!r}). {diag}"
                ),
            }

        # Case 4: finish_reason == "length" with truncated content
        # (content exists but was cut off — still usable, warn only)
        if finish_reason == "length":
            diag = _diag_response_metadata(response, choice, message, content)
            logger.warning("Groq response truncated [length]: %s", diag)
            # Return the truncated content with finish_reason so caller
            # can detect truncation and decide whether to retry.
            return {"success": True, "text": content, "finish_reason": "length"}

        return {"success": True, "text": content, "finish_reason": finish_reason or "stop"}


# ==============================================================
# PROVIDER FACTORY  (cached singleton — always Groq)
# ==============================================================

_provider: GroqProvider | None = None


def get_llm_provider() -> GroqProvider:
    """
    Return the shared GroqProvider instance.

    Raises:
        LLMProviderError: if the provider cannot be initialised
            (e.g. missing GROQ_API_KEY, missing openai package).
    """
    global _provider
    if _provider is None:
        _provider = GroqProvider()
    return _provider
