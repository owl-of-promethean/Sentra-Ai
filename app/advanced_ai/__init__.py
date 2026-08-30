"""
Advanced AI [BETA] — controlled security-validation pipeline.

Turns SOC investigations / audit findings into real, controlled
security validation runs against an authorized sandbox target.

Pipeline:
    SOC investigation / Audit finding
        -> select authorized target (registry only, never client URLs)
        -> create isolated sandbox record
        -> crawl the sandbox attack surface
        -> load existing audit evidence
        -> Groq generates a structured validation plan (Pydantic-validated)
        -> deterministic validator executes safe controlled tests
        -> evidence collected + redacted
        -> Groq evaluates evidence (VULNERABLE / MITIGATED / INCONCLUSIVE)
        -> report + remediation suggestion

Architectural rule: Groq (via app/advanced_ai/llm_provider.py) is the
reasoning layer only.  All HTTP operations are deterministic Python.
The provider NEVER executes requests, shell commands, or arbitrary code,
and its output is never trusted without schema validation.
"""
