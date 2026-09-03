# MITRE ATT&CK Enterprise - Web Application Attacks

## Overview
MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. This document focuses on techniques relevant to web application security monitoring.

## Tactic Categories Relevant to Sentra AI

### 1. Reconnaissance (TA0043)

#### TA0043.T1595 - Active Scanning
**Description**: Adversaries actively probe systems for vulnerabilities and misconfigurations.

**Web-Specific Techniques**:
- Directory traversal scanning
- Parameter enumeration
- Technology stack fingerprinting
- CMS vulnerability scanning

**Behavioral Indicators**:
- High volume of unique paths requested (>10/minute)
- Many HTTP 404 responses in succession
- Rapid path sequences (e.g., /admin, /backup, /db, /.git)
- User-agents matching known scanners
- Time between requests suggesting automation (<1 second)

### 2. Execution (TA0002)

#### TA0002.T1059 - Command and Scripting Interpreter
**Description**: Adversaries execute commands or scripts via web vulnerabilities.

**Injection-Based Execution**:
- SQL injection with out-of-band data extraction
- Remote code execution via vulnerable parameters
- Server-side request forgery (SSRF) for internal command execution

**Behavioral Indicators**:
- POST requests with suspicious payloads
- Responses containing database error messages
- Unusual HTTP response times suggesting processing delays
- Multiple requests following same payload pattern

### 3. Persistence (TA0003)

#### TA0003.T1136 - Create Accounts
**Description**: Adversaries create accounts for persistent access.

**Web-Specific Methods**:
- Registration endpoint exploitation
- Admin account creation through CSRF
- Backdoor account creation via file upload vulnerabilities

**Behavioral Indicators**:
- New account creation from unusual IP addresses
- Account creation immediately followed by privilege escalation attempts
- Multiple failed account creations then success
- Registration without email verification bypass

### 4. Privilege Escalation (TA0004)

#### TA0004.T1068 - Exploitation for Privileges
**Description**: Leveraging vulnerabilities to gain elevated permissions.

**Access Control Bypass Methods**:
- Vertical escalation (user → admin)
- Horizontal escalation (user A → user B)
- JWT token manipulation
- Session fixation attacks

**Behavioral Indicators**:
- Same session accessing resources outside permitted scope
- ID parameter changes correlating with successful unauthorized access
- HTTP method manipulation (GET → POST for privileged actions)
- Header modification (Role: Admin) after initial access

### 5. Credential Access (TA0006)

#### TA0006.T1110 - Brute Force
**Description**: Adversary iteratively uses passwords or password lists to gain access.

**Attack Variants**:
- Password spraying (one password, many accounts)
- Credential stuffing (breached credentials, single account)
- Dictionary attacks on login endpoints

**Behavioral Patterns**:
```
Normal Login Failure Rate: <5%
Suspicious Pattern: >50% failures from single source
Credential Stuffing: Success after 20+ consecutive failures
Password Spray: 100+ different usernames, 1 password, <1% success rate
```

**Indicators**:
- >3 authentication failures from single IP within 1 minute
- Many unique username attempts from same source
- Successful login after extended failure period
- Logins at unusual hours (off-hours targeting)
- Geographic impossibility (logins from different countries within minutes)

#### TA0006.T1111 - Remote Services: Credentials from Password Stores
**Description**: Extracting stored credentials from browser or system stores.

**Not directly observable in web logs**, but may lead to:
- Automated login attempts with discovered credentials
- API key usage patterns indicating compromised tokens

### 6. Discovery (TA0007)

#### TA0007.T1010 - Application Enumeration
**Description**: Mapping applications, services, and infrastructure.

**Reconnaissance Activities**:
- Web technology discovery
- API endpoint mapping
- Directory/file enumeration
- Database schema discovery

**Behavioral Markers**:
- Requests to common sensitive paths (.git/config, .env, wp-config.php)
- Path brute-forcing patterns (/admin, /dashboard, /console, /phpmyadmin)
- Query string fuzzing (?id=1, ?id=1', ?id=1 OR 1=1)
- HEAD/OPTIONS requests to map functionality
- Accept-Language variations to test localization bugs

### 7. Lateral Movement (TA0008)

#### TA0008.T1076 - Remote Services
**Description**: Using valid credentials to access other systems.

**Web Application Context**:
- Jump host behavior (attacker uses compromised server as pivot)
- SSH/RDP connections initiated from web server
- Internal service enumeration after compromise

**Detection Challenges**:
- Traffic appears legitimate from compromised source
- Needs correlation with network logs
- Look for: web server → internal service communication that shouldn't exist

### 8. Exfiltration (TA0010)

#### TA0010.T1041 - Exfiltration Over C2 Channel
**Description**: Data stolen through established channels.

**Web-Specific Methods**:
- Slow exfiltration through normal API responses
- Steganographic embedding in responses
- DNS tunneling from compromised servers
- Cloud storage upload to external buckets

**Behavioral Signals**:
- Abnormal data volumes in outbound responses
- Response sizes significantly larger than typical
- Encrypted data patterns in response bodies
- Unusual outbound traffic during low-activity periods

#### TA0010.T1048 - Exfiltration Over Alternative Protocol
**Description**: Using non-standard protocols for data theft.

**Indicators**:
- POST requests with unusually large payloads
- Frequent uploads to external storage endpoints
- Data transfer during off-hours
- Communication with known malicious domains/IPs

### 9. Command and Control (TA0011)

#### TA0011.T1071 - Application Layer Protocol
**Description**: Communicating using standard web protocols.

**C2 Over HTTP/HTTPS**:
- Beaconing patterns to attacker-controlled domains
- Regular interval requests (every 60 seconds, etc.)
- User-Agent rotation to avoid detection
- TLS certificate anomalies

**Detection Patterns**:
- Outbound requests to unfamiliar domains
- Becon intervals with high precision (<±1 second variance)
- Normal user behavior but wrong destination IPs/domains
- Large data transfers to new destinations

### 10. Defense Evasion (TA0005)

#### TA0005.T1070 - Indicator Removal
**Description**: Clearing logs or disabling monitoring.

**Web Attack Context**:
- Requesting `/logout` or session termination after access
- DELETE requests to log files (if accessible)
- Commands to disable logging services
- Modifying application configuration

**Behavioral Signs**:
- Administrative access followed by config/log changes
- Unusual DELETE requests to normally read-only paths
- Configuration file downloads then modifications
- Service stop/start patterns in logs

#### TA0005.T1202 - Indirect Command Execution
**Description**: Using trusted processes to execute commands.

**Examples**:
- Web server triggering system commands via cron jobs
- Scheduled tasks activated through file uploads
- Dependency on legitimate backup/sync tools

**Detection**:
- Legitimate process making unexpected calls
- Cron job or scheduled task modified recently
- File upload followed by immediate action from same process

## DDoS-Related Techniques

### TA0040 - Impact

#### TA0040.T1499 - Endpoint Disruption
**Description**: Denying availability to legitimate users.

**Layer 3/4 DDoS**:
- Volumetric floods overwhelming bandwidth
- SYN floods exhausting connection tables
- ICMP floods

**Layer 7 DDoS **(Application Layer)
- HTTP GET floods from botnet
- HTTPS floods using encrypted traffic
- Slowloris attacks (connection exhaustion)
- Application protocol abuse (DNS/NTP amplification)

**Behavioral Characteristics**:
```
High Volume + Distributed Sources = Likely DDoS
High Volume + Single Source = Potential DoS or Misconfiguration
Volume Spike + Error Rate Increase = Potential Scan/Attack Hybrid
```

**Legitimate vs Malicious Differentiation**:
- **Legitimate spike**: Follows marketing campaign, news coverage, viral content
- **Malicious DDoS**: Random timing, no business trigger, geographic diversity matches attack patterns
  
### TA0040.T1498 - Network Device Diversion
**Description**: Redirecting network traffic to disrupt service.

**Web-Specific**:
- DNS poisoning redirecting users to fake sites
- BGP hijacking intercepting traffic
- SSL certificate manipulation

---

*Source: MITRE ATT&CK for Enterprise - https://attack.mitre.org/*
