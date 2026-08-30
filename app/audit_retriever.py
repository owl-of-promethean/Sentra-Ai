"""
Audit knowledge retriever for SOC-AI.

Retrieves local security reference material relevant to a code audit.

Design rules:
- Returns REFERENCE MATERIAL only.  Never claims the user's code is vulnerable.
- Parallel structure to the SOC retriever (app/retriever.py) but
  operates on a different knowledge directory and different query type.
- Keeps evidence from source code strictly separate from reference text.
- No network access — Phase 2 uses only local knowledge files.
  Deep Scan (Phase 3+) will add online retrieval via a separate interface.

Query matching strategy:
1. Technology/language labels (e.g. "python", "nodejs") map to relevant files.
2. CWE hints (e.g. "CWE-89") map to relevant files.
3. OWASP hints map to relevant files.
4. SOC trigger context can add extra knowledge files.
5. All matched files are deduped and concatenated.
"""

from __future__ import annotations

import os
from typing import List, Optional

from app.audit_schemas import AuditKnowledgeQuery


# ==============================================================
# KNOWLEDGE DIRECTORY
# ==============================================================

_DEFAULT_KNOWLEDGE_DIR = "data/knowledge"


# ==============================================================
# KEYWORD -> FILE MAPPING
# ==============================================================
#
# Each entry maps a lowercase keyword pattern (substring match) to
# one or more knowledge filenames in data/knowledge/.
#
# These are RETRIEVAL ASSOCIATIONS, not attack classifications.

_TECH_MAP: List[tuple[str, List[str]]] = [
    # Languages / frameworks that commonly appear in web audit contexts
    ("python",     ["web_security_python.md", "cwe_owasp_ref.md"]),
    ("flask",      ["web_security_python.md", "cwe_owasp_ref.md"]),
    ("django",     ["web_security_python.md", "cwe_owasp_ref.md"]),
    ("nodejs",     ["web_security_js.md",     "cwe_owasp_ref.md"]),
    ("javascript", ["web_security_js.md",     "cwe_owasp_ref.md"]),
    ("typescript", ["web_security_js.md",     "cwe_owasp_ref.md"]),
    ("php",        ["web_security_php.md",    "cwe_owasp_ref.md"]),
    ("java",       ["web_security_java.md",   "cwe_owasp_ref.md"]),
    ("ruby",       ["web_security_ruby.md",   "cwe_owasp_ref.md"]),
    ("go",         ["cwe_owasp_ref.md"]),
    ("sql",        ["cwe_owasp_ref.md"]),
]

_CWE_MAP: List[tuple[str, List[str]]] = [
    # Injection
    ("cwe-89",   ["cwe_owasp_ref.md"]),   # SQL injection
    ("cwe-79",   ["cwe_owasp_ref.md"]),   # XSS
    ("cwe-78",   ["cwe_owasp_ref.md"]),   # OS Command injection
    ("cwe-94",   ["cwe_owasp_ref.md"]),   # Code injection
    ("cwe-22",   ["cwe_owasp_ref.md"]),   # Path traversal
    ("cwe-611",  ["cwe_owasp_ref.md"]),   # XXE
    ("cwe-502",  ["cwe_owasp_ref.md"]),   # Deserialization
    # Auth / access control
    ("cwe-306",  ["cwe_owasp_ref.md"]),   # Missing auth
    ("cwe-862",  ["cwe_owasp_ref.md"]),   # Missing authorization
    ("cwe-798",  ["cwe_owasp_ref.md"]),   # Hard-coded credentials
    ("cwe-259",  ["cwe_owasp_ref.md"]),   # Hard-coded password
    ("cwe-287",  ["cwe_owasp_ref.md"]),   # Improper auth
    # Crypto
    ("cwe-326",  ["cwe_owasp_ref.md"]),   # Inadequate key strength
    ("cwe-327",  ["cwe_owasp_ref.md"]),   # Broken crypto
    ("cwe-330",  ["cwe_owasp_ref.md"]),   # Weak randomness
    # Disclosure
    ("cwe-200",  ["cwe_owasp_ref.md"]),   # Info exposure
    ("cwe-209",  ["cwe_owasp_ref.md"]),   # Error message exposure
]

_OWASP_MAP: List[tuple[str, List[str]]] = [
    ("a01",      ["cwe_owasp_ref.md"]),   # Broken Access Control
    ("a02",      ["cwe_owasp_ref.md"]),   # Cryptographic Failures
    ("a03",      ["cwe_owasp_ref.md"]),   # Injection
    ("a04",      ["cwe_owasp_ref.md"]),   # Insecure Design
    ("a05",      ["cwe_owasp_ref.md"]),   # Security Misconfiguration
    ("a06",      ["cwe_owasp_ref.md"]),   # Vulnerable Components
    ("a07",      ["cwe_owasp_ref.md"]),   # Auth Failures
    ("a08",      ["cwe_owasp_ref.md"]),   # Software/Data Integrity
    ("a09",      ["cwe_owasp_ref.md"]),   # Logging Failures
    ("a10",      ["cwe_owasp_ref.md"]),   # SSRF
]

# SOC trigger reasons that also carry code-level security implications
_TRIGGER_MAP: List[tuple[str, List[str]]] = [
    ("multiple failures",    ["cwe_owasp_ref.md"]),
    ("rapid path scanning",  ["cwe_owasp_ref.md"]),
    ("unusual http methods", ["cwe_owasp_ref.md"]),
    ("high error rate",      ["cwe_owasp_ref.md"]),
]


# ==============================================================
# AUDIT KNOWLEDGE RETRIEVER
# ==============================================================


class AuditKnowledgeRetriever:
    """
    Retrieves local security reference material for a code audit.

    The retriever is intentionally stateless: it reads files from disk
    on every call so knowledge files can be updated without restart.

    Results are always labelled as reference material, never as evidence.
    """

    def __init__(self, knowledge_dir: str = _DEFAULT_KNOWLEDGE_DIR) -> None:
        self.knowledge_dir = knowledge_dir

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def retrieve(self, query: AuditKnowledgeQuery) -> dict:
        """
        Return relevant security reference material for the given query.

        Args:
            query: AuditKnowledgeQuery describing technologies, packages,
                   CWE/OWASP hints, and optional SOC trigger context.

        Returns:
            {
              "status":  "success" | "partial" | "no_match" | "empty",
              "sources": [<filename>, ...],
              "context": "<concatenated reference text>"
            }

        The caller must label the returned context as REFERENCE MATERIAL
        in any prompt sent to Gemini.  Never treat it as evidence.
        """
        matched = self._match_sources(query)

        if not matched:
            return {"status": "no_match", "sources": [], "context": ""}

        return self._load_sources(matched)

    def available_files(self) -> List[str]:
        """Return a list of knowledge filenames currently on disk."""
        if not os.path.isdir(self.knowledge_dir):
            return []
        return [
            f for f in os.listdir(self.knowledge_dir)
            if os.path.isfile(os.path.join(self.knowledge_dir, f))
        ]

    # ----------------------------------------------------------
    # INTERNAL HELPERS
    # ----------------------------------------------------------

    def _match_sources(self, query: AuditKnowledgeQuery) -> List[str]:
        """
        Build an ordered, deduplicated list of knowledge filenames from
        the query fields.
        """
        seen: set[str] = set()
        ordered: List[str] = []

        def _add(filenames: List[str]) -> None:
            for fn in filenames:
                if fn not in seen:
                    seen.add(fn)
                    ordered.append(fn)

        # 1. Technologies
        tech_lower = [t.lower() for t in query.technologies]
        for keyword, files in _TECH_MAP:
            if any(keyword in tech for tech in tech_lower):
                _add(files)

        # 2. Package names (check both name and manager)
        pkg_tokens = set()
        for pkg in query.packages:
            pkg_tokens.add(pkg.name.lower())
            pkg_tokens.add(pkg.manager.lower())
        for keyword, files in _TECH_MAP:
            if any(keyword in token for token in pkg_tokens):
                _add(files)

        # 3. CWE hints
        cwe_lower = [c.lower() for c in query.cwe_hints]
        for keyword, files in _CWE_MAP:
            if any(keyword in cwe for cwe in cwe_lower):
                _add(files)

        # 4. OWASP hints
        owasp_lower = [o.lower() for o in query.owasp_hints]
        for keyword, files in _OWASP_MAP:
            if any(keyword in owasp for owasp in owasp_lower):
                _add(files)

        # 5. SOC trigger context
        trigger_lower = [t.lower() for t in query.trigger_context]
        for keyword, files in _TRIGGER_MAP:
            if any(keyword in trig for trig in trigger_lower):
                _add(files)

        return ordered

    def _load_sources(self, filenames: List[str]) -> dict:
        """Read and concatenate knowledge files."""
        loaded: List[str] = []
        missing: List[str] = []
        sections: List[str] = []

        for filename in filenames:
            filepath = os.path.join(self.knowledge_dir, filename)

            if not os.path.isfile(filepath):
                missing.append(filename)
                sections.append(
                    f"[NOTE: Audit knowledge source '{filename}' was not found "
                    f"on disk and could not be loaded.]\n"
                )
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()
                loaded.append(filename)
                sections.append(f"--- REFERENCE: {filename} ---\n\n{content}\n")
            except OSError as exc:
                missing.append(filename)
                sections.append(f"[NOTE: Could not read '{filename}': {exc}]\n")

        context = "\n\n".join(sections)
        status  = "partial" if missing else ("success" if loaded else "no_match")

        return {"status": status, "sources": loaded, "context": context}


# ==============================================================
# MODULE-LEVEL SINGLETON
# ==============================================================

_audit_retriever: Optional[AuditKnowledgeRetriever] = None


def get_audit_retriever() -> AuditKnowledgeRetriever:
    """Return the shared AuditKnowledgeRetriever instance."""
    global _audit_retriever
    if _audit_retriever is None:
        _audit_retriever = AuditKnowledgeRetriever()
    return _audit_retriever


def retrieve_audit_knowledge(query: AuditKnowledgeQuery) -> dict:
    """Convenience function: retrieve audit knowledge for a query."""
    return get_audit_retriever().retrieve(query)
