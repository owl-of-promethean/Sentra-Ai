# Denial of Service (DoS) and DDoS: Behavioral Analysis

## Overview
Understanding the difference between legitimate traffic spikes and malicious denial-of-service attacks is critical for accurate security monitoring. **High request volume alone never proves an attack** - contextual analysis is required.

## Attack Classifications

### 1. Volumetric DDoS (Layer 3/4)

**Goal**: Saturate network bandwidth or infrastructure capacity

**Types**:
- **UDP Floods**: Overwhelming with User Datagram Protocol packets
- **SYN Floods**: Partial TCP handshake exhaustion
- **ICMP Floods**: Ping-based bandwidth consumption
- **Reflective/Amplification**: Using third-party servers to multiply attack volume

**Characteristics**:
```
Traffic Volume: Hundreds of thousands to billions of requests/second
Source Diversity: Thousands to millions of IP addresses globally
Protocol Mix: Often includes non-HTTP traffic
Network Impact: Bandwidth saturation, connection table exhaustion
```

**Behavioral Indicators**:
- Requests per second >> typical baseline (>10x normal)
- Geographic distribution extremely broad (hundreds of countries)
- High packet loss observed by clients
- Network interface utilization near 100%
- Connection tracking table full
- Firewall/CPU utilization at maximum

**Legitimate vs Malicious Differentiation**:
| Factor | Legitimate Spike | Malicious DDoS |
|--------|-----------------|----------------|
| Timing | Follows business event | Random, no trigger |
| Source Diversity | Moderate increase | Massive geographic spread |
| Traffic Pattern | Coordinated (all sources start together) | Chaotic, unsynchronized |
| Protocol | Normal HTTP/HTTPS mix | Unusual protocol ratios |
| Server Load | Gradual degradation | Instant maximum load |

### 2. Application Layer DDoS (Layer 7)

**Goal**: Exhaust application resources (CPU, memory, database connections)

**Types**:
- **HTTP GET Floods**: Many requests to resource-intensive endpoints
- **HTTP POST Floods**: More expensive than GET (request body processing)
- **Slowloris**: Keeping many connections open with minimal data
- **Slow Read**: Slow download speeds to hold connections
- **Cache Poisoning**: Flooding cache with invalid data

**Characteristics**:
```
Traffic Volume: Hundreds to thousands of requests/second (far less than layer 3/4)
Source Diversity: Can be single source or distributed botnet
Impact Focus: Database queries, CPU-intensive operations, file I/O
Detection Difficulty: Harder (looks like legitimate users)
```

**Behavioral Patterns**:

#### Simple GET Flood
```
Requests/minute: >1000
Unique IPs: 50-500 (small botnet)
User Agents: Consistent (botnet uses same browser fingerprint)
Paths Accessed: Same endpoint repeatedly (/login, /search, /api/data)
Response Time: Significantly degraded (>5 seconds)
Error Rate: May remain low (requests "succeed" but don't complete)
```

#### Distributed GET Flood
```
Requests/minute: 500-2000
Unique IPs: Hundreds to thousands
User Agents: Diverse (but often missing cookies/session data)
Paths: Multiple high-cost endpoints targeted
Timing: Simultaneous requests across all sources (coordinated)
Geographic: Widely distributed but unusual patterns for your audience
```

#### Slowloris Attack
```
Connection Count: Maintains hundreds-to-thousands of simultaneous connections
Bytes Transferred: Minimal (<1KB per connection after initial request)
Request Headers: Partial headers sent slowly
Timeout Behavior: Connections held until server max-out reached
Normal Users Affected: Yes (cannot get new connections)
```

### 3. Resource Exhaustion Attacks

**Goal**: Deplete specific system resources (not general bandwidth)

**Examples**:
- **Authentication endpoint flooding**: Exhaust password hashing capacity
- **Search query flooding**: Max out database CPU with complex queries
- **Email submission flooding**: Consume mail queue and SMTP resources
- **File upload floods**: Fill disk space or memory buffers

**Indicators**:
- Specific service hitting resource limits first
- Other services still responding normally
- Response times degrade on particular endpoints only
- Error messages about resource constraints (out of memory, too many connections)

## Distinguishing Legitimate Traffic Spikes from DDoS

### Business Context Analysis

**Legitimate Triggers**:
- Marketing campaigns announced in advance
- Product launches during business hours
- News coverage or social media viral events
- Seasonal patterns (holiday shopping, tax season)
- Email blast sends
- API partner integrations going live

**Questions to Ask**:
1. Did we just announce something public?
2. Is this timing consistent with historical patterns?
3. Are our partners expecting increased usage?
4. Does the traffic geography match our user base?

### Technical Analysis

#### Correlation Matrix

| Metric | Legitimate Growth | DDoS Attack |
|--------|------------------|-------------|
| Request Volume | Increases gradually (minutes/hours) | Sudden spike (seconds) |
| Unique IPs | Proportional to traffic increase | Disproportionate |
| Error Rate | Stable or improves (better scaling) | Increases rapidly |
| Response Times | Degraded but manageable | Severely impacted (>10s) |
| Geography | Matches user base | Random/unusual distribution |
| Referrers | Social media, search engines, direct | None or suspicious sources |
| Session Data | Valid sessions present | Often missing or invalid |

#### Key Differentiators

**Session Analysis**:
- Legitimate spike: High ratio of authenticated users, valid cookies
- DDoS: Mostly unauthenticated, cookie-less requests

**Path Distribution**:
- Legitimate spike: Natural browsing patterns (/home → /products → /cart)
- DDoS: Single path bombardment (/login repeated, /API/endpoint flood)

**Time Patterns**:
- Legitimate spike: Follows timezone patterns, business hours
- DDoS: Can occur any time, often off-hours

**Server Resource Profile**:
- Legitimate spike: All resources scale proportionally
- DDoS: One resource exhausted disproportionately (database vs web server)

## Case Studies: Behavioral Profiles

### Scenario 1: Single-Source DoS (Not DDoS)

```json
{
  "requests_per_minute": 480,
  "unique_ips": 1,
  "source_ip": "203.0.113.50",
  "target_path": "/login",
  "http_methods": {
    "POST": 480
  },
  "error_rate": 0.92,
  "status_codes": {
    "401": 440,
    "200": 40
  },
  "user_agents": {
    "Python-requests/2.28": 480
  }
}
```

**Analysis**: Single IP, high error rate, automated tool signature
**Likely Cause**: Credential stuffing or brute force attempt
**Not**: DDoS (requires multiple sources)

### Scenario 2: Botnet-Based Application DDoS

```json
{
  "requests_per_minute": 3600,
  "unique_ips": 850,
  "target_paths": ["/", "/search", "/product", "/cart"],
  "avg_time_per_request_ms": 8500,
  "error_rate": 0.15,
  "geographic_distribution": {
    "US": 120,
    "CN": 95,
    "RU": 88,
    "IN": 75,
    "BR": 70,
    "...many more...": 402
  }
}
```

**Analysis**: Many IPs, slow response times, global distribution
**Likely Cause**: Coordinated application-layer DDoS
**Action**: Enable rate limiting, DDoS mitigation service

### Scenario 3: Legitimate Viral Event

```json
{
  "requests_per_minute": 2400,
  "unique_ips": 1200,
  "spike_start": "14:32 UTC",
  "spike_trigger": "Twitter mention by @major_influencer",
  "referrers": {
    "twitter.com": 0.72,
    "facebook.com": 0.15,
    "direct": 0.13
  },
  "session_validity": 0.89,
  "error_rate": 0.02,
  "response_time_increase": "1.5x baseline"
}
```

**Analysis**: Clear trigger event, high session validity, moderate errors
**Likely Cause**: Legitimate viral traffic spike
**Action**: Scale infrastructure temporarily, monitor for degradation

## SOC-AI Monitoring Implications

### What to Track (Without Classifying as Attack)

**For High Volume Events**:
1. Request rate vs. baseline (how much higher?)
2. Unique IP count vs. request count (distribution indicator)
3. Geographic diversity score (number of distinct countries)
4. Target endpoint concentration (% to single path)
5. Authentication status ratio (logged-in vs. anonymous)
6. Session cookie validity percentage

**For AI Analysis Later**:
```
Example evidence package:
{
  "behavior_summary": "3800 requests/min, 250 unique IPs, 
                      85% requests to /login, 76 countries represented,
                      3% authenticated, response time 12s avg",
  "baseline_comparison": "19x normal traffic, 3.2x normal unique IPs",
  "business_context_needed": "Verify if marketing campaign running",
  "infrastructure_impact": "Database CPU at 94%, web servers healthy"
}
```

### What NOT to Conclude Yet

❌ "This is a DDoS attack"
✅ "This shows characteristics similar to DDoS patterns; investigate further"

❌ "Botnet activity detected"  
✅ "Multiple sources requesting simultaneously with coordinated patterns"

❌ "Brute force authentication attack"
✅ "Multiple failed authentications from same source with automated timing"

---

*Sources*: CISA DDoS Awareness Guide, NIST SP 800-53 (Denial of Service Controls), OWASP Application Availability Security
