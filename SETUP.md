# SOC-AI Setup Instructions

## Prerequisites

- Python 3.8 or higher
- A Gemini API key from Google AI Studio

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- FastAPI (web framework)
- uvicorn (ASGI server)
- Pydantic (data validation)
- python-dotenv (environment variables)
- google-generativeai (AI API client)
- httpx (HTTP client)

## Step 2: Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit the `.env` file and add your Gemini API key:

```
GEMINI_API_KEY=your-actual-api-key-here
```

**Important**: Never commit your `.env` file to version control!

## Step 3: Run the Application

Option 1 - Using Python directly:

```bash
python -m app.main
```

Option 2 - Using uvicorn:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will start on `http://localhost:8000`

## Step 4: Verify It's Running

Open your browser or use curl:

```bash
curl http://localhost:8000
```

You should see:

```json
{
  "status": "running",
  "service": "SOC-AI",
  "version": "0.1.0",
  "message": "AI-Assisted SOC Analyst System"
}
```

## Testing the Modules

### Test Log Processing

Create a test script `test_log_processor.py`:

```python
from app.log_processor import get_log_processor

processor = get_log_processor()

# Load sample logs
logs = processor.load_logs('sample_logs.json')
print(f"Loaded {len(logs)} logs")

# Prepare investigation window
window = processor.prepare_investigation_window(
    logs=logs,
    trigger_reason="Test investigation"
)
print(f"Investigation ID: {window['id']}")
```

### Test Schemas

```python
from app.schemas import SecurityFinding

finding = SecurityFinding(
    severity="HIGH",
    attack_type="SQL Injection",
    confidence=0.92,
    summary="Test finding",
    evidence=["Evidence item 1"],
    recommended_actions=["Action 1"]
)

print(finding.model_dump_json(indent=2))
```

### Test LLM Integration (requires API key)

```python
from app.llm import analyze_security_event

logs = [
    {
        "timestamp": "2026-08-22T10:30:00Z",
        "event_type": "authentication_failure",
        "source_ip": "192.168.1.100",
        "details": {"username": "admin"}
    }
]

result = analyze_security_event(
    logs=logs,
    context="Suspicious activity detected"
)

if result["success"]:
    print(result["analysis"])
else:
    print("Error:", result["error"])
```

## Project Structure

```
soc-ai/
├── app/                    # Main application code
│   ├── __init__.py
│   ├── main.py            # FastAPI app
│   ├── config.py          # Configuration
│   ├── llm.py             # Gemini client
│   ├── log_processor.py   # Log processing utilities
│   └── schemas.py         # Data models
├── data/
│   ├── logs/              # Security log storage
│   └── knowledge/         # RAG knowledge (future)
├── tests/                 # Tests (future)
├── .env                   # Your API keys (created by you)
├── .env.example           # Template
├── .gitignore
├── requirements.txt
└── README.md
```

## Next Steps

After completing the setup:

1. **Day 1-2**: Implement investigation triggers and detection rules
2. **Day 2-3**: Build the RAG knowledge base with CVE/CWE/OWASP data
3. **Day 3-4**: Integrate source code inspection capabilities
4. **Day 4-5**: Create the SOC analyst dashboard

Happy hacking! 🚀
