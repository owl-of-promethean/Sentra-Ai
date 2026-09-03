# Sentra AI — Frontend

Static single-page frontend for the Sentra AI security operations and audit
platform. No build step and no npm dependencies are required.

## Files

| File | Purpose |
|------|---------|
| `AI hackathon/index.html` | Landing page — default homepage of the site (marketing page with animated background) |
| `AI hackathon/dashboard.html` | Application shell — login screen and the analyst dashboard (Dashboard, Live Logs, SOC, Audit, Copilot AI, Advanced AI pages) |
| `AI hackathon/script.js` | All application logic: JWT session handling, API calls, rendering, mock/demo data |
| `AI hackathon/style.css` | Styling and the animated landing-page background |
| `AI hackathon/landing-bg.js` | Performance-tuned parallax/scene logic for the landing background |

## Running

1. Start the backend first (see the repository root `README.md`):
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
2. Open the frontend. Either open `AI hackathon/dashboard.html` directly in a
   browser, or serve it with any static file server, e.g.:
   ```bash
   cd "frontend/AI hackathon"
   python -m http.server 5500
   ```
   Then visit `http://localhost:5500/` — the landing page is the default
   homepage. The SOC dashboard (login screen) is at
   `http://localhost:5500/dashboard.html`.

## Backend connection

`script.js` contains the API configuration:

```js
const API_CONFIG = {
  USE_REAL_API: true,                      // false = offline mock/demo mode
  BASE_URL:     "http://localhost:8000",   // backend origin
};
```

The backend must run at `BASE_URL`; the FastAPI backend enables CORS for all
origins. Set `USE_REAL_API: false` to explore the UI with built-in mock data
and no backend.

## Demo credentials

`admin@sentra.ai` / `password` (backend demo fallback — see the backend
`SOC_ANALYST_EMAIL` / `SOC_ANALYST_PASSWORD` environment variables).
