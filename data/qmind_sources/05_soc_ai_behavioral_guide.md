# Sentra AI Behavioral Evidence Interpretation Guide

## Purpose
This guide provides cybersecurity knowledge for interpreting behavioral evidence WITHOUT classifying specific attacks. The goal is to help security analysts (and AI systems) understand what observed patterns might indicate, while avoiding premature conclusions.

## Key Principles

### 1. Evidence ≠ Conclusion
**Incorrect**: "This is SQL injection"
**Correct**: "Request parameters contain SQL syntax indicators; investigate further"

**Incorrect**: "DDoS attack detected"
**Correct**: "Traffic volume 19x baseline with characteristics requiring investigation"

### 2. Context Matters
High request volume could be:
- Marketing campaign success ✓
- DDoS attack ✗
- API integration issue ⚠️
- Scheduled job running ⚠️

**Always consider business context before concluding malicious activity.**

### 3. Multiple Explanations Possible
A single pattern rarely indicates one specific cause. Always consider:
- Legitimate user behavior
- Automated tools (valid or malicious)
- Infrastructure issues
- Configuration errors

---

## Behavior Patterns and Potential Explanations

### Pattern A: High Request Volume

**Observed**: 3800 requests/minute from 250 unique IPs

**Possible Explanations **(ranked by likelihood based on context)

1. **Legitimate Traffic Spike**
   - Check: Recent marketing announcement? Viral social media? News coverage?
   - Business trigger present = Likely legitimate
   - Need to scale infrastructure

2. **Application-Layer DDoS**
   - No business trigger visible
   - Geographic distribution unusual for your audience
   - Targeting resource-intensive endpoints
   - Response times severely degraded (>10 seconds)
   - Many sources, coordinated timing

3. **API Integration Issue**
   - Single partner/application causing spike
   - Retry logic malfunctioning
   - Loop in application code

4. **Misconfigured Cron Job**
   - Single source IP
   - Occurs at scheduled intervals
   - High frequency but predictable

**What QMind Can Help With**:
- Typical DDoS behavioral profiles
- Legitimate traffic spike characteristics
- API failure mode examples

---

### Pattern B: Multiple Authentication Failures

**Observed**: 32 failed logins, 6 successes, 38 total attempts in 1 minute

**Possible Explanations**:

1. **Credential Stuffing**
   - Many different usernames, few passwords
   - Known breached credentials in use
   - Success rate higher than random chance (1-5%)
   - Geographic anomalies detected

2. **Password Spraying**
   - Same password across many accounts
   - Low attempt count per account (<3 each)
   - Distributed IP sources
   - Timing designed to avoid lockouts

3. **Brute Force Attack**
   - Same username targeted repeatedly
   - Sequential password variations (Password1, Password2...)
   - Single IP or small IP group
   - Rapid timing (<1 second between attempts)

4. **User Experience Issues**
   - Broken mobile app storing old passwords
   - Keyboard layout changes causing input errors
   - Paste failures (password manager not working)
   - CAPTCHA preventing successful login

**What QMind Can Help With**:
- NIST guidelines for authentication security
- OWASP MFA recommendations
- Normal vs suspicious auth patterns

---

### Pattern C: Rapid Path Enumeration

**Observed**: 150 unique paths requested in 30 seconds from same source

**Possible Explanations**:

1. **Automated Vulnerability Scanning**
   - User-agent matches known scanner (Nikto, Nmap, etc.)
   - Paths include sensitive locations (.git, .env, wp-config.php)
   - Many HTTP 404 responses (paths don't exist)
   - Sequential directory traversal (/dir1, /dir2, /dir3...)

2. **Security Reconnaissance**
   - Testing common vulnerability locations
   - Mapping application structure
   - Preparing for more targeted attacks
   - Often combined with other reconnaissance activities

3. **Broken Bot / Sitemaps**
   - SEO bot misconfigured
   - Old crawl rules from search engine
   - Internal tool scanning deprecated paths

4. **Legitimate Content Discovery**
   - Mobile app discovering available endpoints
   - API documentation auto-generation
   - Developer testing application routes

**What QMind Can Help With**:
- Common vulnerability path patterns
- Scanner user-agent signatures
- Directory enumeration techniques

---

### Pattern D: Unusual HTTP Methods

**Observed**: 25 requests with PUT, DELETE, PATCH methods (normally only GET, POST used)

**Possible Explanations**:

1. **API Functional Usage**
   - RESTful API implementation using full HTTP method spectrum
   - PATCH for partial updates
   - DELETE for resource removal
   - OPTIONS for CORS preflight

2. **Web Application Firewall Testing**
   - Security vendor testing WAF capabilities
   - Method-based filtering evaluation
   - Custom rule development and validation

3. **Attack Probe**
   - Testing if methods are properly restricted
   - Looking for HTTP method confusion vulnerabilities
   - Trying to bypass GET-only security controls
   - TRACE/DEBUG enabled (information disclosure risk)

4. **Misconfigured Client**
   - Framework auto-generated wrong methods
   - Load balancer rewrites methods unexpectedly
   - CDN caching rules interfering

**What QMind Can Help With**:
- HTTP method security considerations
- REST security best practices
- Common web server misconfigurations

---

### Pattern E: High Error Rate

**Observed**: 85% of requests return 4xx/5xx status codes

**Possible Explanations**:

1. **Scanning / Probing Activity**
   - Requesting non-existent paths (404s)
   - Invalid API keys/tokens (401/403)
   - Malformed requests (400 errors)
   - Intentional fault injection testing

2. **Client-Side Issues**
   - Outdated browser versions
   - JavaScript errors breaking requests
   - API version mismatch
   - SSL certificate problems

3. **Server Problems**
   - Resource exhaustion (503 errors)
   - Database failures (500 errors)
   - Misdeployed configuration
   - Dependencies unavailable

4. **Authentication Testing**
   - Credential guessing (401)
   - Permission probing (403)
   - Token expiration followed by refresh attempts

**Correlation Needed**:
- Check time patterns (errors all at once or spread out?)
- Cross-reference with error messages (revealing details?)
- Compare with normal historical error rates
- Look at response payloads (database errors revealed?)

---

## Decision Framework

### Level 1: Initial Assessment
```
Question: Does this activity warrant investigation?

YES IF ANY OF:
- Rate >> baseline (>10x normal)
- Multiple behavioral signals present
- Geographic anomalies detected
- Session invalidity increasing
- Response degradation affecting users

NO IF:
- Explained by business event
- Matches expected automation patterns
- Within acceptable thresholds
- Documented partner/integration activity
```

### Level 2: Evidence Gathering
```
Questions for Investigation:
1. What does our feature calculation show?
2. Are there correlations with other windows?
3. What's the business context?
4. Have we seen this pattern before?
5. What would benign explanations look like?

Document WITHOUT Concluding:
❌ "DDoS attack in progress"
✅ "3800 req/min, 250 IPs, targeting /login endpoint"

❌ "Credential stuffing attack"
✅ "32 auth failures from single source, 28 different usernames"
```

### Level 3: AI-Assisted Analysis
```
Handoff to AI Analyst:
- Provide raw evidence package
- Include calculated features
- List alternative explanations
- Ask specific questions about behavior
- Request guidance on investigation priorities

Expected AI Response:
- Correlate with known threat intelligence
- Suggest additional data to collect
- Provide context about similar patterns
- Recommend investigation next steps
```

---

## Example Evidence Packages

### Example 1: Authentication Event Window

```json
{
  "investigation_id": "abc123-def456",
  "window_start": "2026-08-23T10:00:00Z",
  "window_end": "2026-08-23T10:00:10Z",
  
  "behavioral_summary": {
    "total_auth_attempts": 38,
    "failure_count": 32,
    "success_count": 6,
    "failure_rate": 0.84,
    "unique_usernames": 28,
    "unique_passwords": 5,
    "top_source_ip_attempts": 35,
    "username_targeting": "admin(4x), root(3x), test(5x)"
  },
  
  "alternative_explanations": [
    "Credential stuffing (many usernames, few passwords)",
    "User experience issues (broken password manager)",
    "Automated tool misconfiguration"
  ],
  
  "questions_for_ai": [
    "Is this pattern consistent with credential stuffing?",
    "What breach database checks would help?",
    "Should we block the top source IP?",
    "Are there geographic anomalies?"
  ]
}
```

### Example 2: High Volume Event

```json
{
  "investigation_id": "xyz789-ghi012",
  "window_start": "2026-08-23T14:32:00Z",
  "window_end": "2026-08-23T14:32:10Z",
  
  "behavioral_summary": {
    "requests_per_minute": 3800,
    "baseline_comparison": "19x normal",
    "unique_ips": 250,
    "geographic_spread": "76 countries",
    "target_endpoint_concentration": "/api/login = 85%",
    "authenticated_vs_anonymous": "3% authenticated, 97% anonymous",
    "response_time_degradation": "85ms baseline → 12s average"
  },
  
  "business_context_needed": [
    "Marketing campaign active?",
    "Social media mention recent?",
    "Known partner integrations running?"
  ],
  
  "questions_for_ai": [
    "Does this match application-layer DDoS patterns?",
    "How do we distinguish from legitimate viral traffic?",
    "What mitigation actions are appropriate?"
  ]
}
```

---

## Summary

### Remember:
1. **Evidence first, conclusion later** - Describe what you see, don't label it yet
2. **Context is critical** - Business events explain much apparent anomaly
3. **Multiple hypotheses** - Never assume single explanation for complex behavior
4. **AI augments, doesn't replace** - Human judgment remains essential
5. **Documentation matters** - Clear evidence enables better analysis later

### DO NOT:
- Classify as specific attack type prematurely
- Ignore legitimate business context
- Assume automated = malicious
- Overlook infrastructure issues
- Rely solely on threshold alerts

### DO:
- Calculate comprehensive features
- Document all observations
- Consider alternative explanations
- Gather context before conclusions
- Use AI as analytical assistant
- Preserve raw evidence for review

---

*References*: MITRE ATT&CK Framework, OWASP Top 10, NIST Cybersecurity Framework, CISA Guidance
