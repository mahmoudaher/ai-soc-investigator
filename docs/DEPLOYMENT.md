# Deployment Guide

This guide covers local development and Docker Compose deployment for AI SOC Investigator.

## Prerequisites

Install:

- Python 3.11 or 3.12
- Docker and Docker Compose
- Node.js 22+ for frontend development
- PostgreSQL if running without Docker

External API keys:

- `GEMINI_API_KEY` for LLM-backed agents
- `VIRUSTOTAL_API_KEY` for optional recon enrichment

## Environment Setup

```bash
cp .env.example .env
```

Edit `.env` and set:

```text
GEMINI_API_KEY=<your key>
VIRUSTOTAL_API_KEY=<optional key>
```

For local Python development, the default database URL is:

```text
postgresql+asyncpg://postgres:postgres@localhost:5432/CaseFile
```

For Docker Compose, the API container uses:

```text
postgresql+asyncpg://postgres:postgres@postgres:5432/CaseFile
```

## Docker Compose Deployment

Start PostgreSQL and FastAPI:

```bash
docker compose --env-file .env up --build postgres api
```

Check the API:

```text
http://localhost:8000/health
http://localhost:8000/docs
```

Start the dashboard profile:

```bash
docker compose --env-file .env --profile dashboard up --build
```

Dashboard URL:

```text
http://localhost:3000
```

## Backend Development

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Start PostgreSQL:

```bash
docker compose up -d postgres
```

Create tables:

```bash
python scripts\init_db.py
```

Run the API:

```bash
uvicorn backend.app.main:app --reload --port 8000
```

## Frontend Development

```bash
cd frontend/ai-soc-dashboard
copy env.example.txt .env.local
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

## Alert Ingestion Smoke Test

Ingestion only, no workflow execution:

```bash
curl -X POST "http://localhost:8000/alerts/wazuh?run_workflow=false" \
  -H "Content-Type: application/json" \
  -d "{\"rule\":{\"level\":7,\"description\":\"sshd authentication failed\",\"groups\":[\"sshd\",\"authentication_failed\"]},\"agent\":{\"name\":\"ubuntu-victim\"},\"data\":{\"srcip\":\"10.0.2.15\",\"srcuser\":\"admin\"}}"
```

Full workflow:

```bash
curl -X POST "http://localhost:8000/alerts/wazuh?run_workflow=true" \
  -H "Content-Type: application/json" \
  -d "{\"rule\":{\"level\":10,\"description\":\"SQL Injection attempt detected\",\"groups\":[\"web\",\"attack\"]},\"agent\":{\"name\":\"web-server\"},\"data\":{\"srcip\":\"8.8.8.8\",\"srcuser\":\"root\"}}"
```

The full workflow needs `GEMINI_API_KEY`. VirusTotal enrichment needs `VIRUSTOTAL_API_KEY`.

## Useful Commands

Regenerate workflow docs:

```bash
python scripts\export_workflow_graph.py
```

Run stable non-LLM tests:

```bash
python -m pytest backend\tests\unit\test_wazuh_normalization.py backend\tests\contracts\test_casefile_schema.py -q
```

Compile Python files:

```bash
python -m compileall backend scripts simulate_wazuh.py test_workflow.py
```
