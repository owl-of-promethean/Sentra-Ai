# SOC-AI: AI-Assisted SOC Analyst System

## Overview

SOC-AI is a 5-day hackathon prototype for an AI-assisted Security Operations Center (SOC) analyst system. The project builds a foundation that integrates security log processing with AI-powered threat analysis using Google's Gemini.

## Architecture

```
Vulnerable Website
        ↓
Security Logs
        ↓
Python Backend
        ↓
Log Processing
        ↓
Investigation Trigger
        ↓
RAG Retrieval (Future)
        ↓
Gemini LLM
        ↓
Structured Security Finding
        ↓
SOC Analyst Dashboard (Future)
```

### Current Roles

**Python is responsible for:**
- Receiving logs
- Storing logs
- Grouping logs
- Creating investigation windows
- Triggering investigations
- Passing relevant information to AI
- Receiving structured AI output

**Gemini will be responsible for:**
- Interpreting suspicious activity
- Correlating multiple events
- Explaining why activity is suspicious
- Using retrieved cybersecurity knowledge
- Producing recommendations

**RAG will provide (Future):**
- CVE information
- CWE information
- OWASP Top 10 information
- Security remediation knowledge

## Project Structure

```
soc-ai/
│
├── app/
│   ├── __init__.py           # Package initialization
│   ├── main.py               # FastAPI application entry point
│   ├── config.py             # Environment variable configuration
│   ├── llm.py                # Gemini API client wrapper
│   ├── log_processor.py      # Log processing utilities
│   └── schemas.py            # Pydantic data models
│
├── data/
│   ├── logs/                 # Directory for storing security logs
│   └── knowledge/            # Directory for RAG knowledge base (Future)
│
├── tests/                    # Test files (Future)
│
├── .env.example              # Environment variable template
├── .gitignore
├── requirements.txt
└── README.md
```

## What's Implemented Now

### ✅ Core Application (`main.py`)
- Minimal FastAPI application
- `GET /` endpoint returning status confirmation
- `GET /health` endpoint for health checks
- CORS middleware enabled for development

### ✅ Configuration (`config.py`)
- Environment variable loading via python-dotenv
- Configuration validation for required API keys
- Supports `GEMINI_API_KEY` from `.env` file

### ✅ LLM Client (`llm.py`)
- Clean Gemini API wrapper with `GeminiClient` class
- `analyze_security_event(logs, context)` function for AI analysis
- Log formatting for prompts
- Prompt building with standardized output structure
- Global instance for convenience

### ✅ Data Schemas (`schemas.py`)
- `SecurityFinding`: Structured output model with severity, attack type, confidence, summary, evidence, and recommended actions
- `LogEntry`: Basic unit of security log data
- `InvestigationWindow`: Groups related logs for AI analysis

### ✅ Log Processor (`log_processor.py`)
- `load_logs(filename)`: Load logs from JSON files
- `save_logs(logs, filename)`: Save logs to JSON files
- `group_logs_by_source_ip(logs)`: Group by IP address
- `group_logs_by_time_window(logs, window_minutes)`: Time-based grouping
- `prepare_investigation_window(logs, trigger_reason)`: Create investigation windows
- `filter_logs_by_type(logs, event_types)`: Filter by event type

## What Will Be Implemented Later

### 🔲 Investigation Triggers
- Detection rules for when to trigger investigations
- Pattern matching for suspicious activities
- Threshold-based triggering logic

### 🔲 RAG Knowledge Base
- Integration with vector database
- Loading CVE, CWE, and OWASP data
- Embedding generation and retrieval
- Context enrichment for AI analysis

### 🔲 Vulnerability Scanner
- Source code inspection capabilities
- CWE/OWASP category detection in code
- Static analysis integration

### 🔲 SOC Analyst Dashboard
- Web interface for analysts
- Real-time alert display
- Investigation workflow tools

### 🔲 Logging and Persistence
- Database integration for log storage
- Audit trail functionality
- Historical analysis capabilities

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the example environment file and add your Gemini API key:

```bash
cp .env.example .env
```

Edit `.env` and add your API key:

```
GEMINI_API_KEY=your-actual-api-key-here
```

### 3. Run the Application

```bash
python -m app.main
```

Or using uvicorn directly:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Verify It's Running

Visit `http://localhost:8000` in your browser or use curl:

```bash
curl http://localhost:8000
```

Expected response:
```json
{
  "status": "running",
  "service": "SOC-AI",
  "version": "0.1.0",
  "message": "AI-Assisted SOC Analyst System"
}
```

## Testing the Foundation

### Test the LLM Client

```python
from app.llm import analyze_security_event

# Sample log entries
test_logs = [
    {
        "timestamp": "2026-08-22T10:30:00Z",
        "event_type": "authentication_failure",
        "source_ip": "192.168.1.100",
        "details": {
            "username": "admin",
            "failure_reason": "invalid_password"
        }
    },
    {
        "timestamp": "2026-08-22T10:30:05Z",
        "event_type": "sql_error",
        "source_ip": "192.168.1.100",
        "details": {
            "query_pattern": "OR 1=1",
            "table_accessed": "users"
        }
    }
]

# Analyze the logs
result = analyze_security_event(
    logs=test_logs,
    context="User reported unusual activity on authentication endpoint"
)

print(result["analysis"])
```

### Test the Log Processor

```python
from app.log_processor import get_log_processor

processor = get_log_processor()

# Prepare an investigation window
logs = [...]  # Your log data
window = processor.prepare_investigation_window(
    logs=logs,
    trigger_reason="Multiple failed authentication attempts detected"
)

print(f"Investigation ID: {window['id']}")
print(f"Logs included: {len(window['logs'])}")
```

## Development Guidelines

### Code Style
- Follow PEP 8 standards
- Use docstrings for all public functions
- Type hinting for function parameters and return values

### Modular Design
- Keep modules independent
- Use global convenience functions for simplicity
- Don't couple modules unnecessarily

### Security Considerations
- Never commit `.env` files
- Validate all input data
- Use Pydantic schemas for data validation
- Sanitize any user-provided content passed to AI

## Future Integration Points

When we integrate with other systems, these are the expected interfaces:

### Inbound Logs
- JSON format compatible with `LogEntry` schema
- Standardized timestamp format (ISO 8601)
- Consistent event types

### Outbound Findings
- Output conforming to `SecurityFinding` schema
- Actionable recommendations
- Evidence-backed conclusions

## Contributors

Built for a 5-day hackathon as a foundation for AI-powered security operations.

## License

Internal hackathon project.
