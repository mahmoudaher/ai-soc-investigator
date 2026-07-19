# GitHub Repository Setup Notes

Use this in the GitHub repository About section:

```text
Multi-agent AI SOC investigation platform that ingests Wazuh alerts, normalizes them into case files, orchestrates LangGraph agents for triage/evidence/recon/MITRE/reporting, stores checkpoints in PostgreSQL, and exposes a Next.js analyst dashboard.
```

## Suggested Topics

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

## Short Summary

AI SOC Investigator turns Wazuh security alerts into structured investigation cases. A LangGraph workflow coordinates specialized agents for triage, evidence extraction, enrichment, MITRE mapping, reporting, and finalization, while PostgreSQL stores case snapshots and checkpoints for dashboard review.

## Long Summary

This project demonstrates an AI-assisted SOC investigation workflow with traceable state transitions. Alerts enter through FastAPI, are normalized into a Pydantic `CaseFile`, persisted in PostgreSQL, and processed by specialized agents. The frontend dashboard gives analysts a live view of case status, severity, evidence, MITRE mappings, summaries, and workflow checkpoints.

## README Image Placeholders

The README follows the structure from `ahmed3bahaa/readme-template` and currently uses placeholder images under `docs/images/`:

- `docs/images/logo-placeholder.svg`
- `docs/images/project-overview-placeholder.svg`
- `docs/images/dashboard-placeholder.svg`
- `docs/images/case-detail-placeholder.svg`
- `docs/images/architecture-placeholder.svg`

Replace these files manually with final screenshots or diagrams when they are ready. Keep the same filenames if you do not want to edit the README again.

Do not commit real Wazuh exports, analyst data, credentials, or production alerts. Use synthetic or sanitized visuals for demos.
