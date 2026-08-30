# SOC-AI Security Knowledge Base Configuration

## Overview
This notebook contains cybersecurity knowledge to help interpret behavioral evidence from web application monitoring WITHOUT prematurely classifying specific attacks.

## Contents

### Document 1: OWASP Top 10 Security Risks
**File**: `01_owasp_top10.md`  
**Topics**:
- All 10 critical OWASP risks (2021)
- Behavioral indicators for each category
- Prevention strategies and detection patterns
- Web application security fundamentals

**Key Sections**:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A07: Identification and Authentication Failures
- A10: Server-Side Request Forgery (SSRF)

---

### Document 2: MITRE ATT&CK Enterprise - Web Application Focus
**File**: `02_mitre_attack_web.md`  
**Topics**:
- Mapping MITRE ATT&CK tactics to web behavior
- Reconnaissance, Execution, Persistence techniques
- Credential Access (brute force, password spraying)
- Discovery, Exfiltration, Command & Control patterns
- DDoS-related techniques

**Key Techniques Covered**:
- TA0043.T1595: Active Scanning
- TA0006.T1110: Brute Force
- TA0040.T1499: Endpoint Disruption
- TA0007.T1010: Application Enumeration

---

### Document 3: Denial of Service Analysis
**File**: `03_denial_of_service_analysis.md`  
**Topics**:
- Layer 3/4 vs Layer 7 DDoS distinction
- Volumetric vs Application-layer attacks
- Legitimate traffic spike identification
- Resource exhaustion attack patterns
- Single-source DoS vs distributed DDoS

**Key Frameworks**:
- Legitimate vs malicious differentiation matrix
- Botnet-based attack profiles
- Session analysis approaches
- Business context correlation methods

---

### Document 4: Authentication Attacks
**File**: `04_authentication_attacks.md`  
**Topics**:
- Brute Force (dictionary, rainbow table variants)
- Credential Stuffing (breached credentials)
- Password Spraying (low-and-slow approach)
- Automated credential harvesting + testing
- API key / token abuse patterns

**Detection Guidance**:
- Expected vs anomalous authentication behavior
- Red flags vs yellow flags
- Feature extraction for authentication windows
- False positive risk assessment

---

### Document 5: SOC-AI Behavioral Evidence Guide
**File**: `05_soc_ai_behavioral_guide.md`  
**Purpose**: Interpretation guide for SOC-AI pipeline

**Core Principles**:
1. Evidence ≠ Conclusion
2. Context Matters
3. Multiple Explanations Possible

**Pattern Analyses**:
- Pattern A: High Request Volume
- Pattern B: Multiple Authentication Failures
- Pattern C: Rapid Path Enumeration
- Pattern D: Unusual HTTP Methods
- Pattern E: High Error Rate

**Decision Frameworks**:
- Level 1: Initial Assessment
- Level 2: Evidence Gathering  
- Level 3: AI-Assisted Analysis

**Example Evidence Packages**:
- Authentication event window structure
- High volume event package format
- How to document without classifying

---

## Usage Guidelines

### For QMind Retrieval

When investigating a behavioral pattern, construct queries like:

**For High Volume Events:**
"What cybersecurity behaviors can cause a sudden increase in HTTP request volume, and how can legitimate traffic spikes be distinguished from denial-of-service behavior?"

**For Auth Failures:**
"What does repeated HTTP authentication failure from the same source indicate, and what attack techniques can cause this behavior?"

**For Path Scanning:**
"What can rapid requests to many different web paths indicate during security monitoring?"

**For HTTP Methods:**
"What can unusual HTTP methods such as PUT, DELETE, or PATCH indicate in web security monitoring?"

### Important Notes

1. **DO NOT** use this for hardcoded detection rules
2. **DO** use this for contextual understanding
3. **DO** consider alternative explanations
4. **DO** document evidence before conclusions
5. **DON'T** classify "this is X attack" 
6. **DO** describe observed patterns objectively

---

*Knowledge Sources*: OWASP Foundation, MITRE ATT&CK Framework, NIST Cybersecurity Framework, CISA Guidance
