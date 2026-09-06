# LogSentry

**Turn raw security logs into actionable incidents.**

LogSentry is a lightweight security log analyzer for developers, students, small teams, and system administrators who need understandable findings without operating a full SIEM.

## V1 capabilities

- Linux `auth.log` / SSH authentication parsing
- Nginx and Apache access-log parsing
- Automatic log-format detection
- SSH brute-force detection
- Credential stuffing / username-enumeration detection
- Web reconnaissance / sensitive-path scanning detection
- Suspicious HTTP 401/403/404 activity detection
- SQL-injection indicator detection
- Path-traversal indicator detection
- 0–100 risk scoring and LOW / MEDIUM / HIGH / CRITICAL severity
- MITRE ATT&CK mapping for T1110, T1595, and T1190
- Evidence samples and remediation guidance
- Responsive dark SOC-style dashboard
- Analysis deletion endpoint
- Raw uploads processed in memory and never persisted

## Architecture

```text
.log/.txt upload
      ↓
FastAPI validation (extension + 10 MB limit + UTF-8)
      ↓
Format detector → parser → normalized events
      ↓
Rule engine → incident grouping → risk scoring → MITRE mapping
      ↓
SQLite/PostgreSQL findings storage
      ↓
React dashboard → evidence + remediation
```

## Stack

- Frontend: React, Vite, TypeScript
- Backend: Python, FastAPI, SQLAlchemy
- Development DB: SQLite
- Production DB: PostgreSQL/Supabase via `DATABASE_URL`
- Deployment-ready backend: Docker / Railway

## Local setup

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API: `http://localhost:8000`  
Docs: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Frontend: `http://localhost:5173`

## API

- `POST /api/analyze`
- `GET /api/analyses/{id}`
- `GET /api/analyses/{id}/incidents`
- `GET /api/incidents/{id}`
- `DELETE /api/analyses/{id}`
- `GET /health`

## Security decisions

Uploaded content is treated only as text. LogSentry validates extension and size, requires UTF-8, never executes uploads, never stores the original upload, strips any client path from filenames, uses SQLAlchemy parameterized operations, and renders evidence as React text rather than HTML injection.

The detector searches decoded URL content but never executes or forwards suspicious payloads.

## Demo logs

`demo-logs/ssh-bruteforce.log` produces brute-force and username-enumeration findings.

`demo-logs/web-attacks.log` produces web scanning, abnormal 4xx, SQL injection, and path-traversal findings.

## Tests

```bash
cd backend
pytest -q

cd ../frontend
npm run build
```

CI runs both checks on every push and pull request.

## Benchmark

Run:

```bash
cd backend
python benchmark.py
```

Do not quote benchmark numbers until measured on the target environment. This repository intentionally does not invent performance metrics.

## Detection coverage

V1 contains **6 rule categories**, supports **3 parser families covering 4 named log sources** (Linux auth, SSH auth, Nginx access, Apache access), and maps findings to **3 MITRE ATT&CK techniques**.

## Scope

LogSentry V1 is intentionally not a SIEM. It contains no ML model, LLM dependency, Kafka, Elasticsearch, threat-intelligence API, automatic firewall blocking, OAuth, agent, or multi-tenant system.

## Resume description

> **LogSentry — Security Log Analysis Platform** | Python, FastAPI, React, PostgreSQL  
> Built a lightweight security-analysis platform that parses Linux and web-server logs, detects brute-force attacks, reconnaissance, injection attempts and suspicious activity, assigns risk scores, maps incidents to MITRE ATT&CK techniques, and generates remediation guidance.
