# Authentication Attacks: Brute Force, Credential Stuffing, Password Spraying

## Overview
Authentication attacks exploit weak or compromised credentials. Understanding the behavioral patterns helps distinguish between different attack types without prematurely labeling traffic as malicious.

## Attack Types and Behavioral Patterns

### 1. Brute Force Attacks

**Definition**: Iteratively guessing passwords through repeated attempts

**Types**:
- **Dictionary Attack**: Using word lists (passwords.txt, rockyou.txt)
- **Rainbow Table Attack**: Pre-computed hash lookups
- **Single-Pass Brute Force**: Trying all possible combinations for short passwords
- **Custom Dictionary**: User-specific information (names, birthdays)

**Behavioral Profile**:
```json
{
  "authentication_failures_per_minute": 60,
  "unique_usernames_attempted": 50,
  "source_ips": 1,
  "time_between_attempts_seconds": "<1",
  "success_pattern": "Success on attempt #47 after failures",
  "password_variations": ["Password123", "Password124", "Password125"],
  "target_accounts": ["admin", "root", "administrator"]
}
```

**Indicators**:
- High frequency of POST /login requests (>30/minute from single IP)
- Sequential password patterns in timing
- Successful login after many consecutive failures
- Common usernames targeted first (admin, root, user)
- Short time gaps between attempts (<1 second)

**Legitimate vs Suspicious Differentiation**:
| Factor | Legitimate Failed Logins | Brute Force |
|--------|-------------------------|-------------|
| Frequency | <5 failures/hour per IP | >30 failures/minute |
| User Variety | Same username consistently | Many usernames tried |
| Timing | Natural variation (>2 seconds apart) | Mechanical precision (<1 second) |
| Success Rate | Low (<1%) then normal | High after extended failure period |
| Account Targeting | User's own account | Multiple accounts attempted |

### 2. Credential Stuffing

**Definition**: Using breached credentials from other services to access victim accounts

**Sources of Breached Credentials**:
- Previous data breaches (Have I Been Pwned database)
- Dark web credential sales
- Phishing campaigns
- Malware keyloggers

**Behavioral Profile**:
```json
{
  "requests_per_minute": 200,
  "unique_usernames": 195,
  "unique_passwords": 1,
  "password_reuse_detected": "UserPass2023!" (across 195 accounts),
  "successful_attacks": 8,
  "success_rate": "4%",
  "geographic_distribution": {
    "legitimate_countries": ["US", "CA", "UK"],
    "attack_countries": ["RU", "CN", "VN", "NG"]
  }
}
```

**Indicators**:
- Many different usernames, same password
- Known breached credentials detected via APIs
- Login success rates higher than random chance (1-5% vs <0.1%)
- Geographic anomalies (user normally in US, login from Nigeria)
- Time-based patterns consistent with automated scripts

**Detection Challenges**:
- Single legitimate-looking credential pair works
- No unusual request timing (can be throttled to appear manual)
- No obvious automation signatures (uses headless browsers with cookies)
- May use rotated proxy IPs

### 3. Password Spraying

**Definition**: One password attempted against many accounts

**Goal**: Avoid account lockout by spreading attempts across users

**Behavioral Profile**:
```json
{
  "attempts_per_account": 2-3,
  "total_unique_accounts": 500,
  "same_password_used": "Summer2024!",
  "requests_per_minute": 30,
  "source_ips": 50,
  "timing": "Slow enough to avoid rate limits"
}
```

**Indicators**:
- Many different usernames, low attempt count each
- Same password across all attempts
- Distributed source IPs (to avoid per-IP rate limiting)
- Attempt times spread out (5-10 minutes per full user cycle)
- Success rate: Low but non-zero (if password reused elsewhere)

**Detection Approaches**:
- Cross-user analysis: Many users failed login from same source group
- Password reuse detection: Identical password tried across accounts
- Account-based alerts: Any user receiving >3 failed attempts from diverse sources

### 4. Automated Credential Harvesting + Testing

**Two-Stage Attack**:
1. Phase 1: Collect valid usernames (registration enumeration, email discovery)
2. Phase 2: Test credentials using harvested usernames

**Behavioral Markers**:
```
Phase 1 Pattern:
- GET requests to /register endpoint
- Validating email existence (/validate-email?email=x@y.com)
- Username enumeration APIs
- Error messages revealing account existence

Phase 2 Pattern:
- POST /login with harvested usernames
- Testing common passwords against discovered accounts
- Rapid shift from discovery to exploitation
```

### 5. API Key / Token Abuse

**Not Traditional Authentication**, But Related:
- Stolen API keys used for automated operations
- JWT tokens forged or leaked
- Session hijacking after stealing cookies/tokens
- OAuth token manipulation

**Indicators**:
- API key usage from unexpected geographic locations
- Token expiration errors followed by continued attempts
- Normal user agent replaced with programmatic client
- Request patterns matching bot behavior despite valid credentials

## Business Context Analysis

### Expected Authentication Behavior

**Normal Patterns**:
- Peak login times align with business hours (9-5 local timezone)
- Weekend logins lower than weekdays
- Failed login rate typically <1% of total authentications
- Successful users typically authenticate multiple times per session

**Anomalous Patterns Requiring Investigation**:
```
Red Flags:
- Failed authentication rate >10% from any source IP
- >50% error rate from a single IP during any 10-minute window
- 20+ failed attempts before success (from same source)
- New account created then immediately attempting admin access
- Login success from country where user has never accessed before

Yellow Flags:
- 5-10 failed logins then success
- Login attempts at unusual hours (2-4 AM local time)
- Small increase in error rate (3-5%) sustained over hours
- Slight geographic deviation (user usually US, now Canada)
```

## SOC-AI Feature Extraction

### For Each Authentication Event Window

**Metrics to Calculate**:
1. **Total authentication attempts**: Count of POST /login requests
2. **Failure count**: HTTP 401/403 responses
3. **Unique usernames**: Distinct username parameters submitted
4. **Unique passwords**: Distinct password values observed
5. **Success-after-failure events**: Cases where success follows ≥3 failures
6. **Average interval between attempts**: Temporal clustering indicator
7. **Source IP diversity**: Number of unique IPs making auth requests
8. **Username uniqueness ratio**: Unique usernames ÷ Total attempts
9. **Password reuse score**: Most common password ÷ Total attempts

**Evidence Package Example**:
```json
{
  "window_summary": "Authentication activity analysis",
  "total_attempts": 38,
  "failure_count": 32,
  "success_count": 6,
  "failure_rate": 0.84,
  "unique_usernames": 28,
  "unique_passwords": 5,
  "password_diversity_ratio": 0.13,
  "top_source_ip_attempts": 25,
  "top_source_ip_unique_users": 23,
  "avg_interval_seconds": 1.2,
  "username_targeting_concentration": "admin(5x), root(3x), test(4x)",
  "behavioral_notes": "Many unique usernames, few passwords, high error rate, rapid timing"
}
```

## Decision Framework: When to Flag Without Classifying

### Do NOT conclude: "Brute force attack"
✅ Instead: "High volume authentication failures with characteristics consistent with credential-guessing activity"

### Do NOT conclude: "Credential stuffing"
✅ Instead: "Multiple accounts experiencing failures from same sources, pattern suggests automated credential testing"

### Do NOT conclude: "Password spray attack"
✅ Instead: "Same password attempted across many accounts, distributed timing suggests evasion of lockout thresholds"

### Indicators Warranting AI Investigation Later:

```
Multi-Signal Trigger:
✓ High failure rate (>50%)
✓ Multiple unique usernames from one source
✓ Rapid sequential attempts (<2 seconds apart)
✓ Low success rate overall
✓ Geographic or timing anomalies

Single Signal Triggers (Still Investigate):
✓ Very high absolute failure count (>100/hour) even if distributed
✓ Success after very long failure sequence (>50 attempts)
✓ New account creation immediately followed by privilege escalation attempts
✓ Login from new device/location for previously authenticated user
```

## Response Considerations (For AI to Evaluate Later)

### Immediate Mitigations to Consider:
- Rate limiting on authentication endpoints
- CAPTCHA after failed attempts
- Temporary IP blocking after threshold
- Multi-factor authentication enforcement
- Account lockout (but watch for abuse)

### False Positive Risks:
- Legitimate users having bad keyboard/paste issues
- Broken mobile apps caching old passwords
- Load balancer health checks failing authentication
- Third-party integrations with expired credentials
- Users resetting passwords repeatedly due to forgotten credentials

---

*Sources*: NIST SP 800-63B (Digital Identity Guidelines), OWASP Authentication Cheat Sheet, CISA MFA Guidance
