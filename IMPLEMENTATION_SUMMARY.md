# Sentra AI — Implementation Summary

> Regenerated from the actual repository state on 2026-09-03 after the final
> audit, frontend Git fix, and Sentinel AI → Sentra AI rename. This document
> describes what is **really implemented** — not what was planned.

## Project Overview

Sentra AI is a hackathon-built, AI-assisted Security Operations Center (SOC)
platform. It solves a specific pain point: analysts drown in raw HTTP logs and
disconnected tooling, while generic "AI security assistants" have no real
security context. Sentra AI connects the full chain —

1. **Ingest** live security logs into 10-second behavioral windows.
2. **Investigate** triggered windows with an LLM (Groq `openai/gpt-oss-20b`)
   that receives the evidence plus retrieved security knowledge and must
   produce a structured, validated `SecurityFinding`.
3. **Audit** the *authorized* application source (Quick/Deep scans) that
   correlates runtime behavior with code-level vulnerabilities
   (CWE/OWASP-classified `AuditFinding`s).
4. **Validate** findings via the Advanced AI [BETA] sandbox: allow-listed,
   non-destructive probes against an authorized target, LLM-evaluated verdicts,
   and a mandatory human approval gate.
5. **Explain** any of these objects through a context-restricted Copilot.

A core design rule runs through every module: **Python prepares evidence; the
LLM reasons; Python never classifies attacks; the LLM never executes anything.**

## Current Architecture

```
                        ┌──────────────────────────────────────────┐
                        │              FRONTEND (static SPA)       │
                        │  login · dashboard · live logs · SOC ·    │
                        │  audit · copilot · advanced AI [BETA]     │
                        └───────────────┬──────────────────────────┘
                                        │ fetch + JWT (http://localhost:8000)
                                        ▼
┌───────────────────────────── FASTAPI BACKEND (app/) ─────────────────────────┐
│                                                                              │
│  POST /logs ─▶ LogProcessor (10s windows, thread-safe)                       │
│                     │ behavioral trigger score (generic, no classification)  │
│                     ▼                                                        │
│               Investigation ─▶ Retriever (local knowledge corpus)            │
│                     │                    data/qmind_sources/*.md             │
│                     ▼                                                        │
│               Groq LLM (llm.py, TPM-throttled) ─▶ SecurityFinding            │
│                     │                                                        │
│               History store (data/history.json)                              │
│                     │                                                        │
│  POST /audit/request ─▶ AuthorizedApp registry (server-side trust)           │
│                     ▼                                                        │
│               AuditEngine: SourceCrawler ─▶ DependencyDetector ─▶            │
│               snippet selection ─▶ AuditKnowledgeRetriever ─▶ Groq ─▶        │
│               AuditFinding[] (CWE/OWASP, file/line evidence)                 │
│                     │                                                        │
│  /advanced-ai/jobs ─▶ Orchestrator state machine:                            │
│     sandbox probe ─▶ surface crawl ─▶ LLM/deterministic plan ─▶              │
│     allow-listed validator ─▶ LLM/deterministic evaluation ─▶ verdict        │
│                     │                                                        │
│  POST /copilot/ask ─▶ context reduction ─▶ Groq (context-restricted)         │
└──────────────────────────────────────────────────────────────────────────────┘
```

All state is in-memory (logs, investigations, audits, Advanced AI jobs) except
history, which persists to `data/history.json`.

## Backend

**Framework:** FastAPI (`app/main.py`), served with uvicorn. FastAPI title:
`Sentra AI`, version `0.2.0`. CORS is open (`*`) for the local demo.

### Authentication & session (`app/auth.py`)
- `POST /auth/login` validates credentials from environment variables
  (`SOC_ANALYST_EMAIL` / `SOC_ANALYST_PASSWORD`; demo fallback password
  `password` when unset) and issues an HS256 JWT (python-jose; a fallback
  HMAC implementation is used if jose is unavailable).
- All sensitive endpoints use the `require_auth` bearer-token dependency.
- Tokens default to 8-hour expiry; secret is auto-generated per process unless
  `JWT_SECRET_KEY` is set.
- Single analyst account (prototype scope).

### API surface (all implemented and reachable)
| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /` | public | Service status |
| `GET /health` | public | Configuration validation (reports `degraded` without `GROQ_API_KEY`) |
| `POST /auth/login` | public | Issue JWT |
| `GET /applications` | JWT | List authorized applications (internal paths stripped) |
| `POST /logs` | public | Ingest one security log (required: timestamp, source_ip, method, path, status) |
| `GET /logs/window` | public | Logs in the current 10-second window |
| `GET /logs/stats` | public | Ingestion statistics |
| `POST /logs/process` | public | Manually process the last completed window (dev/testing) |
| `GET /logs/list` | JWT | Filtered/searchable raw logs (event type, method, status class, text search, limit) |
| `GET /logs/export` | JWT | Export logs as JSON/CSV with filters + timeframe presets |
| `GET /investigations` | JWT | Investigation summaries incl. findings and sample logs |
| `GET /investigations/{id}` | JWT | Full investigation detail |
| `POST /audit/request` | JWT | Start a Quick/Deep audit on an authorized app + scope |
| `GET /audit/{audit_id}` | JWT | Audit status/result (internal `source_path` stripped) |
| `GET /investigations/{id}/audit` | JWT | Audit linked to an investigation |
| `GET /history` | JWT | Combined SOC + audit + Advanced AI history with `?q=` search |
| `POST /copilot/ask` | JWT | Context-restricted Copilot Q&A |
| `POST /advanced-ai/jobs` | JWT | Create a sandbox validation job (202 Accepted) |
| `GET /advanced-ai/jobs` | JWT | List jobs |
| `GET /advanced-ai/jobs/{id}` | JWT | Job detail incl. timeline |
| `GET /advanced-ai/jobs/{id}/evidence` | JWT | Redacted evidence bundle |
| `POST /advanced-ai/jobs/{id}/cancel` | JWT | Request cancellation |
| `POST /advanced-ai/jobs/{id}/approve` / `reject` | JWT | Human decision on the proposed fix |
| `GET /advanced-ai/metrics` | JWT | Real job/verdict counts (never fabricated) |

### Log ingestion & processing (`app/log_processor.py`)
- Thread-safe in-memory store; logs grouped into rolling 10-second windows.
- A background asyncio task (`periodic_window_processing`) processes each
  completed window on startup (lifespan-managed).
- Generic behavioral trigger scoring (request volume, error rate, unique paths
  scanning, repeated failures, etc.) — thresholds only, **no attack
  classification** (that is the LLM's job).
- Triggered windows become investigations with deduplicated log samples,
  behavioral features, and retrieved knowledge context.

### LLM integration (`app/llm.py`, `app/advanced_ai/llm_provider.py`, `app/groq_throttle.py`)
- One shared `GroqProvider` (OpenAI-compatible client → Groq) for the whole
  process; the `GeminiClient` class name in `llm.py` is legacy naming kept for
  compatibility — the backend is Groq.
- Investigation prompts are budgeted (~5,500-token hard cap; ≤15 deduplicated
  logs; ≤2,500 chars knowledge); audit prompts ~3,500 tokens with per-section
  truncation that never touches instructions or the output schema.
- JSON extraction handles markdown fences; truncation-aware retry; empty
  response retry; all failures degrade to structured errors, never crashes.
- `groq_throttle.py` enforces a rolling 60-second TPM budget (7,500/8,000) so
  concurrent audits/copilot calls cannot blow the rate limit.

### Code audit pipeline (`app/audit_engine.py` + collaborators)
- `source_crawler.py` crawls the trusted source path (extensions, sizes,
  line-numbered content); `dependency_detector.py` parses manifests
  (requirements, package.json, etc.) for dependencies and technologies.
- Snippet selection prioritizes security-relevant files (auth, routes, DB…)
  and deprioritizes tests/docs.
- `audit_retriever.py` retrieves **local** CWE/OWASP reference material by
  technology/CWE hints — reference text is kept strictly separate from
  observed source evidence in the prompt.
- Quick Scan: ≤6 files / 60 lines / 4k chars. Deep Scan: ≤15 files / 120
  lines / 15k chars + full investigation context incl. raw logs.
- Findings are individually Pydantic-validated; malformed ones are skipped
  rather than failing the audit.

### History (`app/history.py`)
- Append-only JSON store (`data/history.json`) combining SOC, audit, and
  Advanced AI entries; survives restarts; substring search across IDs,
  severities, trigger reasons, and metadata.

## Security Intelligence

### Implemented
- Behavioral trigger engine + LLM investigation with structured
  `SecurityFinding` output (severity, confidence, evidence, alternative
  explanations, recommended actions).
- Knowledge retrieval for investigations (local corpus: OWASP Top 10, MITRE
  ATT&CK web, DoS analysis, authentication attacks, behavioral guide) and for
  audits (CWE/OWASP reference).
- Authorized application registry — the single source of truth for audit
  targets; scope/endpoint allow-lists; client-supplied paths/URLs are never
  trusted; internal paths never serialized to the frontend.
- AI code audits with CWE/OWASP classification and file/line evidence.
- Advanced AI [BETA] validation pipeline (planner/validator/evaluator with
  LLM + deterministic fallbacks, payload allow-list, request budget, evidence
  redaction, approval/reject endpoints).
- Context-restricted Copilot with backend-side context validation and token
  budget enforcement.

### Partially implemented
- Advanced AI sandbox is **logical isolation bound to a trusted target** —
  no container/VM; the demo registry points at the platform's own code as a
  stand-in customer application.
- "Approve fix" records the human decision; applying a fix automatically is
  intentionally out of scope (human gate by design).
- Multi-user RBAC is absent — a single analyst account exists.

### Planned / not implemented
- Online CVE/vulnerability-database retrieval for Deep Scans (the audit
  retriever explicitly documents this as a future interface; current Deep
  Scan = wider local coverage + full investigation context).
- Vector-DB/embedding-based RAG (current retrieval is keyword-mapped local
  files).
- Persistent database for logs/investigations/audits (in-memory today).
- Automated test suite (none exists — see Testing).

## Frontend

**Stack:** vanilla HTML/CSS/JS single-page application — no framework, no
build step, no npm dependencies. External library: Anime.js via CDN (charts
and animations only).

**Location:** `frontend/AI hackathon/` (`index.html`, `dashboard.html`,
`script.js`, `style.css`, `landing-bg.js`).

**Pages / features (all implemented):**
- **Login** — posts to `/auth/login`, stores the JWT in `localStorage`
  (`sentra-token`); any later 401 force-logs-out. Demo hint
  `admin@sentra.ai / password`.
- **Dashboard** — real data from `/investigations` + `/logs/stats`: session
  stats, critical/high counts, threat-activity chart (canvas + anime.js),
  recent alerts (clickable → event modal), audit/SOC timeline.
- **Live Logs** — filterable table (event type, method, status class, search),
  live indicator, pause, and a JSON/CSV export modal with timeframe presets
  (`/logs/list`, `/logs/export`).
- **SOC** — security event stream from investigations with severity filters;
  event modal shows AI analysis, recommended actions, raw log evidence, and
  shortcuts to Audit / Copilot / Advanced AI.
- **Audit** — authorized-application selector (from `/applications`), scope +
  endpoint constraints, Quick/Deep toggle, progress bar, history grid;
  findings modal shows CWE/OWASP, severity, evidence, remediation.
- **Copilot AI** — chat UI bound to a selected investigation/audit/job
  context; quick-action prompts; refuses off-context questions.
- **Advanced AI [BETA]** — remediation queue, 7-step job timeline, proposed
  code diff (original/modified), validation tests, verdict report with
  reasoning and remediation, explicit Approve/Reject human gate.
- **Landing page** (`index.html` — the default homepage of the site) with an
  animated SVG background
  (CSS keyframes + `landing-bg.js` parallax, reduced-motion aware).

**API communication:** all requests go through `apiRequest()` with the Bearer
token; base URL `http://localhost:8000` (`API_CONFIG.BASE_URL` in
`script.js`); the backend enables CORS. `USE_REAL_API: false` switches the
whole UI to built-in `MOCK_DATA` for offline demos.

**How it is started/accessed:** serve the folder with any static server
(`python -m http.server 5500` inside `frontend/AI hackathon`) and open
`http://localhost:5500/` — the landing page is the default homepage; the SOC
dashboard is at `/dashboard.html` (opening it directly from disk also works).
The backend must be running for real data.

## Data Flow (end-to-end)

1. A monitored application (or the curl command from the README) sends a log
   to `POST /logs` — validated (6 required fields), stamped, stored.
2. Logs accumulate in the current 10-second window; the background processor
   closes each window, computes behavioral features, and scores triggers.
3. On trigger, an investigation is created: logs + features + knowledge
   context (retrieved from `data/qmind_sources/` by trigger-reason mapping).
   The investigation is persisted to history and handed to the LLM as a
   background task.
4. Groq receives the budgeted prompt (instructions / metadata / features /
   log sample / knowledge / JSON schema) and returns a `SecurityFinding`
   validated by Pydantic; the investigation status moves to `analyzed`
   (or `analysis_failed` with a structured error). History is updated.
5. The analyst signs in (JWT) and works the dashboard/SOC pages, which poll
   the protected endpoints.
6. From an investigation, the analyst requests an audit: the backend resolves
   the authorized app + scope to a trusted `source_path`, crawls code,
   detects dependencies, retrieves CWE/OWASP reference material, and sends
   the evidence to Groq → validated `AuditFinding[]` with file/line locations.
7. Optionally, a finding (or whole audit) is sent to Advanced AI: a sandbox
   job crawls the authorized target, the LLM (or deterministic fallback)
   plans allow-listed probes, the validator executes them and collects
   redacted evidence, and the LLM (or fallback) evaluates a verdict
   (VULNERABLE / MITIGATED / INCONCLUSIVE) with remediation — awaiting
   explicit human approval/rejection.
8. At any point the analyst can ask Copilot about a specific investigation,
   audit, or job; the backend builds a token-budgeted, context-restricted
   prompt and Groq answers only about that object.

## Testing

**Automated tests: none.** There is no `tests/` directory and no test files
in the repository (the previous summary referenced a `test_pipeline.py` that
does not exist). Verification is manual:

- Backend import + startup check (`uvicorn app.main:app`) — verified working.
- `GET /` and `GET /health` respond correctly — verified working.
- Login → JWT → protected endpoints flow — verified working.
- Log ingestion → window processing → investigation creation — verified
  working (LLM analysis requires a valid `GROQ_API_KEY`).
- Frontend served statically and reaching the backend — verified working.

## Repository Structure

```
soc-ai-audit/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app, lifespan, all core routes
│   ├── config.py               # GROQ_* configuration + validation
│   ├── auth.py                 # JWT login / require_auth
│   ├── authorized_apps.py      # Trusted application registry
│   ├── log_processor.py        # 10s windows, triggers, investigations
│   ├── retriever.py            # SOC knowledge retrieval
│   ├── llm.py                  # Groq client + prompts (investigation/audit)
│   ├── groq_throttle.py        # Rolling TPM limiter
│   ├── audit_engine.py         # Quick/Deep scan orchestration
│   ├── audit_retriever.py      # Audit knowledge retrieval (local)
│   ├── source_crawler.py       # Source crawling
│   ├── dependency_detector.py  # Dependency/tech detection
│   ├── audit_schemas.py        # Audit models (AuditResult, AuditFinding…)
│   ├── schemas.py              # SecurityFinding etc.
│   ├── history.py              # JSON history store
│   ├── copilot_context.py      # Copilot context reduction + prompts
│   └── advanced_ai/            # Advanced AI [BETA]
│       ├── __init__.py, events.py, schemas.py
│       ├── routes.py           # /advanced-ai/* endpoints
│       ├── orchestrator.py     # Job state machine + JobStore
│       ├── sandbox.py          # Sandbox lifecycle + reachability probe
│       ├── crawler.py          # Attack-surface crawler
│       ├── attack_planner.py   # Deterministic fallback planner
│       ├── gemini_bridge.py    # LLM plan/evaluate bridge (Groq-backed)
│       ├── validator.py        # Allow-listed probe executor
│       ├── evaluator.py        # Deterministic fallback evaluator
│       └── llm_provider.py     # Shared Groq provider
├── frontend/
│   ├── README.md               # Frontend docs
│   └── AI hackathon/
│       ├── index.html          # Marketing landing page (default homepage)
│       ├── dashboard.html      # SPA shell (login + 6 pages + modals)
│       ├── script.js           # All logic (3749 lines) + MOCK_DATA
│       ├── style.css           # Styling + animated background
│       └── landing-bg.js       # Landing background motion
├── data/
│   ├── knowledge/cwe_owasp_ref.md       # Audit reference material
│   ├── qmind_sources/                   # SOC knowledge corpus (5 docs + INDEX)
│   ├── logs/sample_logs.json            # Sample logs
│   └── history.json                     # Persisted demo history
├── .env.example
├── .gitignore
├── README.md
├── SETUP.md
├── IMPLEMENTATION_SUMMARY.md            # This file
├── requirements.txt
└── Sentra AI — Final Project Summary.pdf
```

## Configuration

Environment variables (template in `.env.example`; real `.env` is
git-ignored):

| Variable | Required | Default | Notes |
|---|---|---|---|
| `GROQ_API_KEY` | Yes | — | All AI features fail without it; `/health` reports degraded |
| `GROQ_BASE_URL` | No | `https://api.groq.com/openai/v1` | OpenAI-compatible endpoint |
| `GROQ_MODEL` | No | `openai/gpt-oss-20b` | Reasoning model |
| `SOC_ANALYST_EMAIL` | No | `admin@sentra.ai` | Login email (also accepts `admin`) |
| `SOC_ANALYST_PASSWORD` | No | `password` (demo fallback) | Set a real value outside demos |
| `JWT_SECRET_KEY` | No | random per process | Set for tokens that survive restarts |
| `TOKEN_EXPIRE_HOURS` | No | `8` | JWT lifetime |
| `ADVANCED_AI_USE_GEMINI` | No | `true` | `false` forces offline/deterministic Advanced AI demos |

## Known Limitations

- In-memory state: logs, investigations, audits, and Advanced AI jobs are lost
  on restart (only `data/history.json` persists).
- Single analyst account with a demo fallback password; credentials compared
  in plain text (prototype scope).
- Auto-generated JWT secret invalidates sessions on restart unless
  `JWT_SECRET_KEY` is set.
- CORS allows all origins — demo-grade configuration.
- Advanced AI sandbox is logical isolation, not containerized; the demo
  target registry points at the platform's own source as a stand-in.
- Deep Scan prompts truncate source evidence to the token budget (by design,
  documented in `llm.py`).
- Knowledge retrieval is keyword-mapped local files — no vector DB, no online
  CVE feeds.
- No automated tests; verification is manual.
- The frontend hard-codes the backend origin (`localhost:8000`).
- The backend does not serve the frontend; both run separately.
- The bundled PDF (`Sentra AI — Final Project Summary.pdf`) is a binary
  artifact generated before the rename and still carries the old name inside.

## Hackathon Status

**Demo-ready end to end** (with a valid `GROQ_API_KEY`):

1. Login → JWT session → authorized application list.
2. Log ingestion → 10-second window processing → behavioral trigger →
   knowledge retrieval → Groq investigation → structured finding on the SOC
   dashboard and history.
3. Quick/Deep code audits of the authorized app with CWE/OWASP findings and
   file/line evidence.
4. Advanced AI [BETA] sandbox validation with plan → probes → verdict →
   human approval gate (offline deterministic mode available via
   `ADVANCED_AI_USE_GEMINI=false`).
5. Context-restricted Copilot Q&A.
6. Live-log filtering and JSON/CSV export.
7. Landing page + full dashboard UI in light/dark themes.

**Not demo-ready / absent:** automated tests, multi-user auth, persistent
storage, online CVE enrichment, vector-based RAG.
