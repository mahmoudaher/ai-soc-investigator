# Visuals Guide

Yes, this project should include visuals. The system is both security-focused and workflow-heavy, so diagrams and screenshots will make the repository much easier to understand.

## Recommended Folder

Create:

```text
docs/assets/
```

Use names like:

```text
docs/assets/dashboard-overview.png
docs/assets/cases-list.png
docs/assets/case-detail.png
docs/assets/new-case-ingestion.png
docs/assets/checkpoint-timeline.png
docs/assets/workflow-graph.png
docs/assets/database-schema.png
```

## Best Visuals To Add

1. Dashboard overview

Shows the analyst landing page and summary metrics.

2. Case list

Shows active and historical investigations.

3. Case detail

Shows one investigation with status, entities, evidence, MITRE mappings, and report output.

4. New case ingestion

Shows how an analyst can send a Wazuh alert from the UI.

5. Workflow diagram

Use the Mermaid graph from `docs/workflow.md` or export it as an image.

6. Database/checkpoint diagram

Show the relationship between `cases`, `case_checkpoints`, and the embedded `CaseFile` snapshot.

## README Screenshot Section

After screenshots are added, place a section like this near the top of `README.md`:

```md
## Screenshots

### Dashboard Overview
![Dashboard Overview](docs/assets/dashboard-overview.png)

### Case Detail
![Case Detail](docs/assets/case-detail.png)

### Workflow
![Workflow Graph](docs/assets/workflow-graph.png)
```

## Priority

If you only add three visuals, add:

1. dashboard overview
2. case detail
3. workflow graph

Those three communicate the product, the analyst experience, and the backend architecture quickly.

