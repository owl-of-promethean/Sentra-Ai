"""
Security Knowledge Retriever for SOC-AI.

Loads relevant cybersecurity knowledge from local Markdown files
based on behavioral trigger reasons produced by the investigation
trigger layer.

Design principles:
- One trigger reason may map to MULTIPLE knowledge sources.
- Multiple trigger reasons accumulate sources (no duplicates).
- Never classifies attacks — only returns knowledge text.
- Fully independent of FastAPI and Gemini.
- No new dependencies beyond the standard library.
"""

import os
from typing import List

# ==============================================================
# TRIGGER-TO-SOURCE MAPPING
# ==============================================================
#
# Each keyword pattern maps to one or more knowledge filenames.
# These are KNOWLEDGE ASSOCIATIONS, not attack classifications.
#
# The mapping is checked via substring match against each
# trigger reason string (case-insensitive).
#
# A single trigger reason can match multiple entries, and
# multiple trigger reasons accumulate sources without duplicates.

_KEYWORD_MAP: List[tuple[str, List[str]]] = [
    (
        "high request volume",
        [
            "03_denial_of_service_analysis.md",
            "05_soc_ai_behavioral_guide.md",
        ],
    ),
    (
        "multiple failures",
        [
            "04_authentication_attacks.md",
            "05_soc_ai_behavioral_guide.md",
        ],
    ),
    (
        "high error rate",
        [
            "03_denial_of_service_analysis.md",
            "05_soc_ai_behavioral_guide.md",
        ],
    ),
    (
        "rapid path scanning",
        [
            "02_mitre_attack_web.md",
            "05_soc_ai_behavioral_guide.md",
        ],
    ),
    (
        "unusual http methods",
        [
            "01_owasp_top10.md",
            "02_mitre_attack_web.md",
            "05_soc_ai_behavioral_guide.md",
        ],
    ),
]

# Default: always include the behavioral guide when at least one
# reason matched (it is the primary interpretation reference).
_FALLBACK_SOURCE = "05_soc_ai_behavioral_guide.md"


# ==============================================================
# RETRIEVER CLASS
# ==============================================================


class SecurityKnowledgeRetriever:
    """
    Retrieves relevant cybersecurity knowledge for a triggered
    investigation window.

    The retriever is stateless after construction: it resolves
    file paths once and reads from disk on every retrieve() call
    so that knowledge files can be updated without restarting.
    """

    def __init__(
        self,
        knowledge_dir: str = "data/qmind_sources",
    ) -> None:
        """
        Args:
            knowledge_dir: Path to the directory containing
                           knowledge Markdown files.
        """
        self.knowledge_dir = knowledge_dir

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def retrieve(self, trigger_reasons: List[str]) -> dict:
        """
        Return relevant knowledge for the given trigger reasons.

        Args:
            trigger_reasons: List of human-readable trigger strings
                produced by the investigation trigger layer, e.g.
                ["high request volume", "multiple failures from 10.0.0.1"].

        Returns:
            A dict with three keys:

            status  – "success"  : at least one source loaded fully
                      "partial"  : some sources found but some files missing
                      "no_match" : no trigger reason matched any keyword
                      "empty"    : trigger_reasons was empty

            sources – list of filenames that were matched and read

            context – concatenated Markdown content from all loaded sources
        """
        if not trigger_reasons:
            return {"status": "empty", "sources": [], "context": ""}

        matched_files = self._match_sources(trigger_reasons)

        if not matched_files:
            return {"status": "no_match", "sources": [], "context": ""}

        return self._load_sources(matched_files)

    # ----------------------------------------------------------
    # INTERNAL HELPERS
    # ----------------------------------------------------------

    def _match_sources(self, trigger_reasons: List[str]) -> List[str]:
        """
        Derive an ordered, deduplicated list of knowledge filenames
        from the trigger reasons.

        Uses case-insensitive substring matching so that reasons like
        "multiple failures from 10.10.10.50" still match the
        "multiple failures" keyword entry.
        """
        seen: set[str] = set()
        ordered: List[str] = []

        lowered_reasons = [r.lower() for r in trigger_reasons]

        for keyword, filenames in _KEYWORD_MAP:
            keyword_lower = keyword.lower()
            # A keyword matches if any trigger reason contains it.
            if any(keyword_lower in reason for reason in lowered_reasons):
                for filename in filenames:
                    if filename not in seen:
                        seen.add(filename)
                        ordered.append(filename)

        return ordered

    def _load_sources(self, filenames: List[str]) -> dict:
        """
        Read each knowledge file and combine their contents.

        Returns a result dict with status, sources, and context.
        Missing files are skipped with a warning comment inserted
        into the context; they do not raise exceptions.
        """
        loaded_sources: List[str] = []
        missing_sources: List[str] = []
        sections: List[str] = []

        for filename in filenames:
            filepath = os.path.join(self.knowledge_dir, filename)

            if not os.path.isfile(filepath):
                missing_sources.append(filename)
                # Insert a placeholder so the LLM knows a source is absent.
                sections.append(
                    f"[NOTE: Knowledge source '{filename}' was not found "
                    f"on disk and could not be loaded.]\n"
                )
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()

                loaded_sources.append(filename)
                sections.append(
                    f"--- SOURCE: {filename} ---\n\n{content}\n"
                )

            except OSError as exc:
                missing_sources.append(filename)
                sections.append(
                    f"[NOTE: Could not read '{filename}': {exc}]\n"
                )

        context = "\n\n".join(sections)

        if not loaded_sources and missing_sources:
            status = "partial"
        elif missing_sources:
            status = "partial"
        else:
            status = "success"

        return {
            "status": status,
            "sources": loaded_sources,
            "context": context,
        }


# ==============================================================
# MODULE-LEVEL SINGLETON
# ==============================================================

_retriever: SecurityKnowledgeRetriever | None = None


def get_retriever() -> SecurityKnowledgeRetriever:
    """Return the shared SecurityKnowledgeRetriever instance."""

    global _retriever

    if _retriever is None:
        _retriever = SecurityKnowledgeRetriever()

    return _retriever


def retrieve_knowledge(trigger_reasons: List[str]) -> dict:
    """Convenience function: retrieve knowledge for given reasons."""

    return get_retriever().retrieve(trigger_reasons)
