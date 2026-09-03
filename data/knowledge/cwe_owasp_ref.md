# CWE / OWASP Security Reference — Sentra AI Audit Knowledge Base

> **IMPORTANT — FOR AI USE**: This document is REFERENCE MATERIAL only.
> The presence of a pattern described here does NOT mean the application under
> audit is vulnerable.  Gemini must ground every finding in observed source-code
> evidence from the crawler, not in the descriptions below.

---

## OWASP Top 10 (2021) Quick Reference

### A01:2021 — Broken Access Control
**Description**: Users can act outside of their intended permissions.

**Common patterns in source code**:
- Missing authorization checks before resource access
- Relying solely on client-supplied parameters (e.g., `user_id` in URL) without server-side verification
- CORS misconfiguration allowing untrusted origins
- Privilege-escalation paths accessible without role checks

**CWE associations**: CWE-862 (Missing Authorization), CWE-306 (Missing Authentication)

**Remediation direction**: Deny by default; enforce server-side authorization on every request.

---

### A02:2021 — Cryptographic Failures
**Description**: Sensitive data not properly protected in storage or transit.

**Common patterns in source code**:
- Hard-coded secrets, API keys, or passwords in source files
- Use of weak/broken algorithms: MD5, SHA-1, DES, RC4
- HTTP instead of HTTPS for sensitive data
- Predictable random values for security tokens

**CWE associations**: CWE-327 (Broken Crypto), CWE-798 (Hard-coded Credentials), CWE-330 (Weak Randomness)

**Remediation direction**: Use modern, well-reviewed crypto libraries; never hard-code secrets; use environment variables or secrets managers.

---

### A03:2021 — Injection
**Description**: Untrusted data sent to an interpreter as part of a command or query.

**Common patterns in source code (SQL Injection — CWE-89)**:
- String concatenation or f-string interpolation used to build SQL queries
- User input directly embedded in `WHERE`, `INSERT`, `UPDATE`, or `DELETE` clauses
- Absence of parameterized queries / prepared statements

**Common patterns (XSS — CWE-79)**:
- User-supplied data rendered directly into HTML responses without escaping
- `innerHTML` assignment with unvalidated data in JavaScript
- Template engines with auto-escaping disabled

**Common patterns (Command Injection — CWE-78)**:
- `os.system()`, `subprocess.run()`, `exec()`, `eval()` with user-controlled input
- Shell=True with unsanitized input in Python subprocess calls

**Remediation direction**: Parameterized queries; output encoding; avoid dynamic command construction with user input.

---

### A04:2021 — Insecure Design
**Description**: Missing or ineffective security controls by design.

**Indicators**: Absence of rate limiting, no account lockout, business logic flaws allowing unauthorized state transitions.

---

### A05:2021 — Security Misconfiguration
**Description**: Insecure default configurations, unnecessary features enabled, verbose error messages.

**Common patterns in source code**:
- Debug mode enabled in production (`DEBUG=True`, `app.debug = True`)
- Stack traces / detailed error messages returned to clients
- Default credentials not changed
- Unnecessary endpoints or admin interfaces exposed

**CWE associations**: CWE-209 (Error Message Information Exposure), CWE-200 (Information Exposure)

---

### A06:2021 — Vulnerable and Outdated Components
**Description**: Using components with known vulnerabilities.

**Note for AI**: Detecting an outdated package is a HINT to investigate further.
It is NOT proof that the application is exploited or exploitable.
The actual vulnerability must be confirmed in the application's usage of the component.

---

### A07:2021 — Identification and Authentication Failures
**Description**: Weaknesses in authentication and session management.

**Common patterns in source code**:
- Weak password policies enforced in code
- Session tokens with insufficient entropy
- Missing session invalidation on logout
- JWT tokens with `alg: none` accepted

**CWE associations**: CWE-287 (Improper Authentication), CWE-259 (Hard-coded Password)

---

### A08:2021 — Software and Data Integrity Failures
**Description**: Code and infrastructure that does not protect against integrity violations.

**Common patterns**: Deserialization of untrusted data without validation.

**CWE associations**: CWE-502 (Deserialization of Untrusted Data)

---

### A09:2021 — Security Logging and Monitoring Failures
**Description**: Insufficient logging prevents detection and response.

---

### A10:2021 — Server-Side Request Forgery (SSRF)
**Description**: Application fetches a remote resource without validating the user-supplied URL.

**Common patterns in source code**:
- `requests.get(user_input)` without URL scheme/host validation
- Fetching URLs from user-provided webhook or callback fields

**CWE associations**: CWE-918 (SSRF)

---

## Selected CWE Details

### CWE-89: SQL Injection
**Abstraction**: Base  
**Description**: The product constructs all or part of an SQL command using externally-influenced input, allowing an attacker to modify the command.  
**Key indicator in code**: String concatenation/formatting used in SQL query construction alongside unsanitized user input.  
**Safe alternative**: Parameterized queries / prepared statements / ORM query builders that never concatenate raw input.

### CWE-79: Cross-site Scripting (XSS)
**Abstraction**: Base  
**Description**: User-controllable input is included in output without neutralization, enabling script injection in victim browsers.  
**Variants**: Reflected, Stored, DOM-based.  
**Safe alternative**: Context-aware output encoding; Content-Security-Policy headers; avoid `innerHTML`/`document.write` with untrusted data.

### CWE-78: OS Command Injection
**Abstraction**: Base  
**Description**: User-controlled data reaches a system shell command without proper neutralization.  
**Key indicator**: `shell=True` in subprocess with user input; `os.system(f"cmd {user_data}")`.  
**Safe alternative**: Use subprocess with list arguments (no shell); validate/reject shell metacharacters.

### CWE-22: Path Traversal
**Abstraction**: Base  
**Description**: User input used to construct file paths without stripping `../` sequences.  
**Key indicator**: `open(user_supplied_filename)` without path normalization and restriction to a safe directory.  
**Safe alternative**: Use `os.path.realpath()` + prefix check; reject inputs with `..`.

### CWE-798: Hard-coded Credentials
**Abstraction**: Base  
**Description**: Credentials are stored directly in source code.  
**Key indicator**: String literals resembling passwords, API keys, or tokens assigned to variables like `password`, `secret`, `api_key`, `token` directly in source.  
**Safe alternative**: Environment variables; secrets managers; configuration files excluded from source control.

### CWE-287: Improper Authentication
**Abstraction**: Class  
**Description**: Authentication mechanism can be bypassed or is absent where required.

### CWE-306: Missing Authentication for Critical Function
**Abstraction**: Base  
**Description**: Critical functionality is accessible without authentication.

### CWE-502: Deserialization of Untrusted Data
**Abstraction**: Base  
**Description**: Deserializing data from an untrusted source can lead to arbitrary code execution.  
**Key indicator**: `pickle.loads(user_data)`, `yaml.load(user_data)` (without `Loader=yaml.SafeLoader`), `unserialize()` in PHP with user input.

### CWE-209: Generation of Error Message Containing Sensitive Information
**Abstraction**: Base  
**Description**: Error messages reveal implementation details, stack traces, or internal paths to users.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Abstraction**: Class  
**Description**: Information is exposed to actors who should not have access.

---

## Evidence vs. Reference — Guidance for AI

When producing findings, Gemini must distinguish:

**OBSERVED EVIDENCE** (from the crawler):
- Actual source-code lines containing the pattern
- File path and exact line numbers
- The specific user input flow from entry point to sink

**REFERENCE MATERIAL** (from this document):
- General descriptions of vulnerability classes
- CWE/OWASP category definitions
- Example patterns that MAY indicate a vulnerability

A finding is only valid when observed evidence exists.
Reference material alone is insufficient to claim a vulnerability.
