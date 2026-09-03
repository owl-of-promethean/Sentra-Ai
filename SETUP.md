# Sentra AI — Setup Instructions

## Prerequisites

- Python 3.10+
- A Groq API key (free at <https://console.groq.com>) — powers all AI features
- A modern browser

## Step 1 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs FastAPI, uvicorn, Pydantic, python-dotenv, the OpenAI client
(used against Groq's OpenAI-compatible API), httpx, and python-jose.

## Step 2 — Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```
GROQ_API_KEY=your-groq-api-key
```

Optional (see `.env.example` for all variables):

- `SOC_ANALYST_EMAIL` / `SOC_ANALYST_PASSWORD` — analyst login (demo fallback
  is `admin@sentra.ai` / `password`)
- `JWT_SECRET_KEY` — set a stable secret if sessions should survive restarts
- `ADVANCED_AI_USE_GEMINI=false` — forces the deterministic (offline) mode for
  Advanced AI demos

**Never commit your `.env` file.**

## Step 3 — Start the backend

```bash
uvicorn app.main:app --reload --port 8000
```

The API is served at `http://localhost:8000` (interactive docs at
`/docs`).

## Step 4 — Verify the backend

```bash
curl http://localhost:8000/
curl http://localhost:8000/health
```

`/` returns the running service; `/health` reports `healthy` once
`GROQ_API_KEY` is configured (`degraded` otherwise).

## Step 5 — Start the frontend

The frontend is static — no build step. In a second terminal:

```bash
cd "frontend/AI hackathon"
python -m http.server 5500
```

Open <http://localhost:5500/> — the landing page is the default homepage.
The SOC dashboard is at <http://localhost:5500/dashboard.html>; sign in
there with `admin@sentra.ai` / `password`. Opening `dashboard.html` directly
in a browser also works. The frontend expects
the backend at `http://localhost:8000` (`API_CONFIG.BASE_URL` in `script.js`).

## Step 6 — Exercise the pipeline

```bash
# Ingest a suspicious log (repeat a few times within 10 seconds)
curl -X POST http://localhost:8000/logs -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-09-03T10:00:00Z","source_ip":"185.220.101.42","method":"POST","path":"/api/login","status":401,"user_agent":"curl/8.0"}'
```

After ~10 seconds the backend prints a window-processing summary; a triggered
investigation is analyzed by Groq in the background and appears on the
dashboard SOC page, dashboard alerts, and in `GET /history`.

From the SOC event modal you can then start an audit of the authorized
application, send findings to Advanced AI validation, and ask Copilot about
any object.

## Troubleshooting

- **`/health` says degraded** — `GROQ_API_KEY` is missing in `.env`; AI
  features will return structured errors until it is set.
- **Login fails** — check `SOC_ANALYST_EMAIL` / `SOC_ANALYST_PASSWORD`; the
  demo fallback password `password` only applies when no password is set.
- **Frontend shows "Cannot reach the backend"** — the backend is not running
  on port 8000, or `API_CONFIG.BASE_URL` in `script.js` points elsewhere.
- **Advanced AI jobs fail** — sandbox targets must be reachable at the URL
  configured in the authorized application registry; set
  `ADVANCED_AI_USE_GEMINI=false` for offline deterministic runs.
