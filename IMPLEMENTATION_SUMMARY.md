# 10-Second Log Processing Pipeline - Implementation Summary

## Files Changed

### 1. `app/log_processor.py` (MODIFIED)
**New Functionality:**
- Added in-memory log storage with thread safety (`self._logs`, `_lock`)
- Created 10-second time window organization (`_window_logs`)
- Added `ingest_log()` method for receiving logs via API
- Added `_get_current_window_key()` to calculate 10-second windows
- Added `get_logs_for_current_window()` to retrieve logs in current window
- Added `get_all_logs()` to get complete log history
- Added `clear_old_logs()` to prevent unbounded memory growth
- Added `process_windows_summary()` to generate processing summaries

**Key Methods:**
```python
ingest_log(log_data: dict) -> dict        # Receives single log entry
_get_current_window_key() -> str          # Returns "2026-08-22T22:10:00"
get_logs_for_current_window() -> List     # Get logs in current 10s window
process_windows_summary() -> dict         # Get window timing and count
```

### 2. `app/main.py` (MODIFIED)
**New Endpoints:**
- `POST /logs` - Ingest security log entries
- `GET /logs/window` - View current window summary
- `GET /logs/stats` - View overall statistics

**Background Task:**
- `periodic_window_processing()` - Runs every 10 seconds
- Prints formatted window summaries to console
- Format:
  ```
  ============================================================
  WINDOW PROCESSING SUMMARY
  ============================================================
  Window: 2026-08-22T22:10:00 → 2026-08-22T22:10:10
  Logs received: 15
  ============================================================
  ```

### 3. `test_pipeline.py` (NEW)
Comprehensive test script that:
- Verifies server is running
- Ingests 15 sample logs from various IPs
- Checks window summaries
- Views overall statistics
- Tests validation errors
- Waits for automatic window processing

---

## How the 10-Second Window Works

### Window Calculation Logic

```python
# Round down to nearest 10 seconds
now = datetime.utcnow()
window_start = now.replace(
    second=(now.second // 10) * 10,  # Example: 22:10:45 → 22:10:40
    microsecond=0
)
```

**Examples:**
- Time: 22:10:45 → Window: **22:10:40** (active until 22:10:50)
- Time: 22:10:55 → Window: **22:10:50** (active until 22:11:00)
- Time: 22:11:03 → Window: **22:11:00** (active until 22:11:10)

### Flow Diagram

```
Incoming Log → POST /logs
       ↓
Ingested with UUID → ingest_log()
       ↓
Organized by window key → _window_logs["2026-08-22T22:10:40"]
       ↓
Stored in memory (thread-safe)
       ↓
Every 10 seconds → periodic_window_processing()
       ↓
Print summary → "Window: 22:10:40 → 22:10:50 | Logs: 15"
```

### Thread Safety

All operations use a locking mechanism:
```python
with self._lock:
    # Safe access to shared data structures
```

This prevents race conditions when multiple API requests arrive simultaneously.

---

## How to Test POST /logs

### Method 1: Using curl (Quick Test)

Open PowerShell and run:
```powershell
curl -X POST http://localhost:8000/logs `
  -H "Content-Type: application/json" `
  -d '{
    "timestamp": "'$(Get-Date -Format 'o')'Z",
    "source_ip": "192.168.1.100",
    "method": "GET",
    "path": "/api/test",
    "status": 200
  }'
```

Expected response:
```json
{
  "status": "ingested",
  "log_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-08-22T22:10:00+00:00Z",
  "source_ip": "192.168.1.100"
}
```

### Method 2: Using Python

Create `quick_test.py`:
```python
import requests

response = requests.post('http://localhost:8000/logs', json={
    "timestamp": "2026-08-22T22:10:00Z",
    "source_ip": "192.168.1.100",
    "method": "POST",
    "path": "/api/login",
    "status": 401,
    "user_agent": "Mozilla/5.0"
})

print(response.json())
```

### Method 3: Using the Test Script (Recommended)

```bash
pip install requests  # If not already installed
python test_pipeline.py
```

This automatically sends 15 sample logs and shows you all the results.

---

## Additional Endpoints

### GET /logs/window
View the most recent window summary:
```bash
curl http://localhost:8000/logs/window
```

Response:
```json
{
  "window_start": "2026-08-22T22:10:00",
  "window_end": "2026-08-22T22:10:10",
  "log_count": 15,
  "status": "processed"
}
```

### GET /logs/stats
View overall statistics:
```bash
curl http://localhost:8000/logs/stats
```

Response:
```json
{
  "total_logs_ingested": 15,
  "logs_in_current_window": 8,
  "window_seconds": 10
}
```

---

## Logging Requirements

### Required Fields
- `timestamp`: ISO 8601 format (e.g., `"2026-08-22T22:10:00Z"`)
- `source_ip`: Client IP address (e.g., `"192.168.1.100"`)
- `method`: HTTP method (e.g., `"GET"`, `"POST"`)
- `path`: Request path (e.g., `"/api/login"`)
- `status`: HTTP status code (e.g., `200`, `401`)

### Optional Fields
- `user_agent`: Browser/client string (defaults to `"unknown"`)
- Any additional metadata fields will be preserved

### Example Payload
```json
{
  "timestamp": "2026-08-22T22:10:00Z",
  "source_ip": "192.168.1.100",
  "method": "POST",
  "path": "/api/login",
  "status": 401,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
```

---

## What Happens Next?

The current implementation only collects and groups logs. Future enhancements will add:

1. **Investigation Triggers**: Detect patterns like brute force, SQL injection attempts
2. **RAG Integration**: Retrieve relevant CVE/CWE knowledge before analysis
3. **Gemini Analysis**: Send grouped logs + retrieved knowledge to LLM
4. **Security Findings**: Generate structured findings with recommendations
5. **Dashboard Display**: Show results on SOC analyst interface

But for now, the foundation proves that our backend can:
✅ Receive logs via API  
✅ Store them in memory safely  
✅ Group them into 10-second windows  
✅ Automatically summarize each window  
✅ Provide query endpoints for inspection  

---

## Running the Application

```bash
cd c:\Users\hamza\OneDrive\Desktop\try\soc-ai
python -m app.main
```

Then wait ~10 seconds after sending logs to see the window summary printed to console.
