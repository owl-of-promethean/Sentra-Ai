# OWASP Top 10 Security Risks

## Overview
The OWASP Top 10 represents the most critical web application security risks based on consensus from security professionals worldwide.

## Current OWASP Top 10 (2021)

### A01: Broken Access Control
**Description**: Users can act outside of their intended permissions, accessing unauthorized resources or performing actions they shouldn't.

**Common Vulnerabilities**:
- Vertical privilege escalation (low-level users accessing admin functions)
- Horizontal privilege escalation (accessing other users' data)
- Unrestricted resource access
- Improper authentication enforcement

**Prevention**:
- Implement proper authorization checks on every request
- Use role-based access control (RBAC)
- Deny by default, explicitly allow authorized access
- Validate access controls server-side, not client-side

### A02: Cryptographic Failures
**Description**: Sensitive data is not properly protected during storage or transmission.

**Key Points**:
- Missing encryption in transit (HTTP instead of HTTPS)
- Weak cryptographic algorithms (MD5, SHA1, DES)
- Hardcoded secrets or weak key management
- Insecure random number generation

**Prevention**:
- Use TLS 1.2+ for all data in transit
- Apply strong encryption standards (AES-256) for data at rest
- Never store sensitive data unnecessarily
- Use secure key management practices

### A03: Injection
**Description**: Flawed code allows attackers to inject malicious commands or queries.

**Common Types**:
- SQL Injection (SQLi)
- Command Injection
- LDAP Injection
- SMTP Injection

**Attack Indicators**:
- Unsanitized user input reaching database queries
- Error messages revealing database structure
- Unexpected behavior suggesting command execution

**Prevention**:
- Use parameterized queries or prepared statements
- Input validation and sanitization
- Stored procedures with limited permissions
- Web Application Firewalls (WAF)

### A04: Insecure Design
**Description**: Applications lack proper security architecture and design patterns.

**Key Issues**:
- Missing threat modeling
- No secure by design principles
- Trust boundaries not defined
- Insecure default configurations

**Prevention**:
- Adopt secure software development lifecycle (SSDLC)
- Implement threat modeling early
- Use trusted security frameworks
- Regular security architecture reviews

### A05: Security Misconfiguration
**Description**: Security settings are incomplete, insecure, or overly permissive.

**Common Problems**:
- Default credentials active
- Verbose error messages in production
- Unnecessary features enabled
- Missing security headers
- Cloud misconfigurations

**Prevention**:
- Follow security hardening guides
- Remove default accounts and passwords
- Disable unnecessary services
- Implement security headers (CSP, X-Frame-Options)
- Regular configuration audits

### A06: Vulnerable and Outdated Components
**Description**: Using components with known vulnerabilities.

**Risks**:
- Old CMS versions with public exploits
- Legacy frameworks without patches
- Third-party libraries with CVEs
- End-of-life software in use

**Prevention**:
- Maintain component inventory
- Monitor for security advisories
- Update dependencies regularly
- Use software composition analysis (SCA) tools

### A07: Identification and Authentication Failures
**Description**: Weak authentication mechanisms allow attackers to compromise credentials.

**Common Issues**:
- Password spraying attacks
- Credential stuffing from breached passwords
- Brute force protection missing
- Session fixation vulnerabilities
- Weak password policies

**Indicators of Attack**:
- Multiple failed login attempts from same IP
- High volume of authentication requests
- Successful logins after many failures
- Unusual login times or locations

**Prevention**:
- Enforce multi-factor authentication (MFA)
- Implement account lockout thresholds
- Use CAPTCHA after failed attempts
- Monitor for credential breach databases
- Secure session management with rotation

### A08: Software and Data Integrity Failures
**Description**: Attacks involving untrusted content or automated processes.

**Risks**:
- Unsigned or unverified code execution
- CI/CD pipeline compromises
- Unauthorized third-party integrations
- Deserializing untrusted data

**Prevention**:
- Verify integrity of updates and extensions
- Use digital signatures for code
- Secure CI/CD pipelines
- Avoid deserialization of untrusted data

### A09: Security Logging and Monitoring Failures
**Description**: Inadequate logging allows attackers to operate undetected.

**Problems**:
- Log events not captured
- Insufficient detail for incident response
- No real-time alerting
- Logs easily modified by attackers

**Prevention**:
- Comprehensive security event logging
- Centralize logs outside application scope
- Implement real-time alerting
- Protect log integrity
- Regular log review and auditing

### A10: Server-Side Request Forgery (SSRF)
**Description**: Attackers coerce servers into making requests to internal resources.

**Impact**:
- Internal network reconnaissance
- Access to cloud metadata services
- Bypassing firewalls
- Scanning internal systems

**Prevention**:
- Validate and sanitize URL inputs
- Block private IP ranges
- Use allowlists for URLs
- Disable redirect following
- Network segmentation

## Behavioral Indicators for Sentra AI

When analyzing logs, look for these patterns:

**Injection Attempts**:
- Request parameters with SQL keywords (UNION, SELECT, DROP)
- Special characters in unexpected fields
- Database error messages in responses

**Authentication Attacks**:
- Rapid succession of POST /login requests
- HTTP 401 status codes > 50% of attempts
- Single IP with multiple username variations
- Known compromised credentials from breach lists

**Access Control Violations**:
- ID manipulation in URLs (/user/123 → /user/124)
- Admin paths accessed without authorization
- HTTP 403 responses followed by success
- Parameter tampering for privilege changes

**Reconnaissance/Scanning**:
- Sequential path enumeration (/admin, /backup, /db, etc.)
- Many HTTP 404 responses
- Unusual HTTP methods (OPTIONS, TRACE, PUT)
- User-agent strings matching scanners (Nikto, Nmap)

**Cryptographic Issues**:
- Requests over HTTP (not HTTPS)
- Responses with weak cipher negotiation
- SSL/TLS certificate warnings in client logs

---

*Source: OWASP Foundation - https://owasp.org/www-project-top-ten/*
