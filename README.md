# AI SOC Investigator

AI SOC Investigator is a multi-agent incident analysis platform for security operations workflows. It ingests security alerts, normalizes them into a shared case file, runs a LangGraph investigation pipeline, persists each case and workflow checkpoint in PostgreSQL, and exposes the results through a FastAPI API and Next.js analyst dashboard.

The project is designed around one core idea: a SOC alert should not be handled by one large, unstructured model call. Instead, specialized agents collaborate on the same structured `CaseFile`, so every investigation step is traceable, reviewable, and ready for analyst handoff.

## Project Description

When a Wazuh alert arrives, the backend normalizes it into a consistent schema, creates a case, stores the initial checkpoint, and optionally runs the full AI investigation workflow in the background. The workflow uses dedicated agents for triage, evidence extraction, enrichment, MITRE ATT&CK mapping, reporting, and final status handling.

The dashboard reads live case data from the FastAPI backend, including case status, severity, entities, evidence, timelines, recommendations, MITRE mappings, and checkpoints.

## Key Features

- Wazuh alert ingestion endpoint.
- Normalized alert model for consistent downstream processing.
- Shared Pydantic `CaseFile` state passed between agents.
- LangGraph workflow orchestration.
- LLM-backed triage, evidence extraction, MITRE mapping, and reporting.
- VirusTotal enrichment support in the recon agent.
- PostgreSQL persistence for cases and workflow checkpoints.
- FastAPI endpoints for case listing, case details, and checkpoint history.
- Next.js dashboard for reviewing cases and creating new investigations.
- Docker Compose deployment for PostgreSQL, API, and optional dashboard.
- Test fixtures for Wazuh alert normalization and case serialization contracts.

## Architecture At A Glance

```text
Wazuh alert or simulated alert
        |
FastAPI POST /alerts/wazuh
        |
Wazuh normalization
        |
CaseFile creation
        |
PostgreSQL case + ingest checkpoint
        |
LangGraph workflow
        |
triage -> evidence -> recon -> mapper -> reporter -> finalizer
        |
PostgreSQL case updates + per-node checkpoints
        |
Next.js SOC dashboard
```

## Tech Stack

| Layer | Technology |
| --- | --- |
| API | FastAPI |
| Agent orchestration | LangGraph |
| AI integration | LangChain Google GenAI / Gemini |
| Data models | Pydantic |
| Database | PostgreSQL |
| ORM | SQLAlchemy async |
| Frontend | Next.js, React, TypeScript |
| UI | shadcn/ui, Tailwind CSS |
| Deployment | Docker Compose |

## Repository Structure

```text
.
+-- backend/                  # FastAPI app, agents, models, database layer, tests
+-- docs/                     # Architecture, workflow, deployment, and GitHub docs
+-- frontend/ai-soc-dashboard # Next.js analyst dashboard
+-- infrastructure/           # Infrastructure notes
+-- scripts/                  # Database and workflow utility scripts
+-- tool-runner/              # Placeholder for future isolated tool execution
+-- workers/                  # Placeholder for future async workers
+-- docker-compose.yml        # Local compose stack
+-- requirements.txt          # Python backend dependencies
+-- simulate_wazuh.py         # Sends a sample Wazuh alert to the API
+-- test_workflow.py          # Local workflow/database demo script
```

## Agent Workflow

The active LangGraph pipeline is:

1. `triage`: classifies the alert and records initial analysis.
2. `evidence`: extracts technical artifacts from the raw alert.
3. `recon`: enriches observables with VirusTotal when configured.
4. `mapper`: maps investigation context to MITRE ATT&CK techniques.
5. `reporter`: generates the final investigation summary and recommendations.
6. `finalizer`: marks the case as completed or failed.

The generated Mermaid workflow is available in [docs/workflow.md](docs/workflow.md).

## API Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `POST` | `/alerts/wazuh` | Ingest a Wazuh alert and optionally run the workflow |
| `GET` | `/cases` | List recent cases |
| `GET` | `/cases/{case_id}` | Read one case file |
| `GET` | `/cases/{case_id}/checkpoints` | Read workflow checkpoint history |

Use `run_workflow=false` on `/alerts/wazuh` for an ingestion-only smoke test that does not call LLM or enrichment services.

## Environment Variables

Copy the example file:

```bash
cp .env.example .env
```

Important variables:

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Yes | Async PostgreSQL connection string |
| `AUTO_CREATE_TABLES` | Dev only | Creates tables at FastAPI startup when set to `true` |
| `GEMINI_API_KEY` | Workflow | Enables Gemini-backed agents |
| `VIRUSTOTAL_API_KEY` | Optional | Enables VirusTotal enrichment in recon |
| `AI_SOC_API_URL` | Frontend | Server-side dashboard URL for FastAPI |
| `NEXT_PUBLIC_AI_SOC_API_URL` | Frontend | Browser-visible FastAPI URL |

## Quick Start With Docker Compose

1. Clone the repository:

```bash
git clone https://github.com/mahmoudaher/ai-soc-investigator.git
cd ai-soc-investigator
```

2. Create your environment file:

```bash
cp .env.example .env
```

3. Add at least `GEMINI_API_KEY` if you want the full AI workflow.

4. Start PostgreSQL and the API:

```bash
docker compose --env-file .env up --build postgres api
```

5. Open the API docs:

```text
http://localhost:8000/docs
```

6. Run an ingestion-only smoke test:

```bash
curl -X POST "http://localhost:8000/alerts/wazuh?run_workflow=false" \
  -H "Content-Type: application/json" \
  -d '{"rule":{"level":7,"description":"sshd authentication failed","groups":["sshd","authentication_failed"]},"agent":{"name":"ubuntu-victim"},"data":{"srcip":"10.0.2.15","srcuser":"admin"}}'
```

7. Start the dashboard too:

```bash
docker compose --env-file .env --profile dashboard up --build
```

Dashboard URL:

```text
http://localhost:3000
```

## Local Development

Backend:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python scripts\init_db.py
uvicorn backend.app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend/ai-soc-dashboard
copy env.example.txt .env.local
npm install
npm run dev
```

## Testing And Validation

Syntax/import-safe validation:

```bash
python -m compileall backend scripts simulate_wazuh.py test_workflow.py
```

Stable non-LLM tests:

```bash
python -m pytest backend/tests/unit/test_wazuh_normalization.py backend/tests/contracts/test_casefile_schema.py -q
```

Full workflow tests currently require the LLM/enrichment-era tests to be aligned with the active Gemini-based agents and external-service configuration.

## Suggested GitHub Description

```text
Multi-agent AI SOC investigation platform that ingests Wazuh alerts, normalizes them into case files, orchestrates LangGraph agents for triage/evidence/recon/MITRE/reporting, stores checkpoints in PostgreSQL, and exposes a Next.js analyst dashboard.
```

Suggested topics:

```text
soc
ai-security
incident-response
wazuh
fastapi
langgraph
multi-agent
mitre-attack
postgresql
nextjs
cybersecurity
security-automation
```

## Should This Project Add Visuals?

Yes. This project should absolutely add visuals. A SOC investigation system is workflow-heavy, so screenshots and diagrams help visitors understand the value quickly. Add the dashboard overview, case list, case detail, alert ingestion form, workflow graph, and database/checkpoint diagram.

See [docs/VISUALS.md](docs/VISUALS.md) for a recommended visual checklist.

## Security Notes

This is a research/prototype project. Do not commit real `.env` files, API keys, Wazuh exports, production alerts, or analyst data. Use synthetic or sanitized alerts for demos.
