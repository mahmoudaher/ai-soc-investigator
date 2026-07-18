# Architecture

AI SOC Investigator is organized around a shared investigation state called `CaseFile`. The backend receives alerts, normalizes them, stores them, and passes them through a LangGraph workflow where each agent contributes a focused part of the investigation.

## Runtime Flow

```text
Alert source
  +-- Wazuh JSON alert or simulated alert
        |
FastAPI ingestion
  +-- POST /alerts/wazuh
        |
Normalization
  +-- backend/app/normalization/wazuh.py
        |
Case state
  +-- backend/app/models/casefile.py
        |
Persistence
  +-- cases + case_checkpoints in PostgreSQL
        |
LangGraph workflow
  +-- triage -> evidence -> recon -> mapper -> reporter -> finalizer
        |
Dashboard and API reads
  +-- GET /cases, GET /cases/{case_id}, GET /cases/{case_id}/checkpoints
```

## Backend Components

### FastAPI App

File: `backend/app/main.py`

Responsibilities:

- expose API routes
- normalize incoming Wazuh alerts
- create and persist `CaseFile` objects
- create ingest checkpoints
- run the agent workflow in the background when requested
- expose case and checkpoint read APIs for the dashboard

### Database Layer

Files:

- `backend/app/db/models.py`
- `backend/app/db/repository.py`
- `backend/app/db/session.py`

The database stores two main tables:

- `cases`: current case snapshot and searchable metadata
- `case_checkpoints`: immutable checkpoint snapshots after ingest and workflow nodes

The app uses async SQLAlchemy with PostgreSQL JSONB columns for complete case snapshots.

### CaseFile Model

File: `backend/app/models/casefile.py`

Important fields:

- identifiers: `case_id`, `source`
- classification: `status`, `severity`, `category`, `subcategory`, `priority`
- investigation state: `entities`, `evidence`, `timeline`, `hypotheses`
- AI output: `triage`, `mitre`, `recommendations`, `summary`
- execution tracking: `agent_runs`

The model is designed so every agent can update a narrow section without losing context from previous agents.

## Agent Responsibilities

### `triage`

File: `backend/app/agents/triage.py`

Classifies the alert using Gemini structured output and appends a triage timeline event and agent run record.

### `evidence`

File: `backend/app/agents/evidence.py`

Extracts technical artifacts such as IPs, domains, users, hashes, and URLs from the raw alert and writes them as evidence items.

### `recon`

File: `backend/app/agents/recon.py`

Uses VirusTotal when `VIRUSTOTAL_API_KEY` is configured to enrich IP and domain observables with reputation data.

### `mapper`

File: `backend/app/agents/mapper.py`

Maps alert context and evidence to MITRE ATT&CK techniques using structured LLM output.

### `reporter`

File: `backend/app/agents/reporter.py`

Generates the final incident summary and analyst recommendations from the accumulated case state.

### `finalizer`

File: `backend/app/agents/finalizer.py`

Sets the terminal case status. Cases with agent errors become `failed`; otherwise they become `completed`.

## Frontend Components

Frontend root:

```text
frontend/ai-soc-dashboard
```

The dashboard uses Next.js and reads the backend through API helper functions. Key pages include:

- dashboard overview
- case list
- case detail
- new case ingestion form
- checkpoint/history views

The FastAPI URL is controlled with:

- `AI_SOC_API_URL`
- `NEXT_PUBLIC_AI_SOC_API_URL`

## Workflow Diagram

The generated workflow graph is stored in [workflow.md](workflow.md). Regenerate it with:

```bash
python scripts/export_workflow_graph.py
```

## Design Notes

- Keep `CaseFile` backward-compatible because checkpoints store full snapshots.
- Add a checkpoint whenever a workflow node mutates the case.
- Keep agent ownership narrow to avoid accidental overwrites.
- Prefer normalized alert fields over source-specific Wazuh paths in downstream agents.
- Keep external lookups optional so ingestion-only testing remains possible.
