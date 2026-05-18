from datetime import datetime, timezone
from backend.app.models.casefile import CaseFile, Recommendation, TimelineEvent, AgentRun

async def reporter_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)

    mitre_count = len(state.mitre)
    evidence_count = len(state.evidence)
    summary = f"Automated Investigation Complete: Processed {evidence_count} evidence items and successfully mapped {mitre_count} MITRE ATT&CK techniques."

    new_recs = []
    if mitre_count > 0:
        technique_names = ", ".join([m.name for m in state.mitre])
        rec = Recommendation(
            action="Isolate affected endpoint and block identified malicious IPs/Domains at the firewall.",
            priority="high",
            risk="high",
            rationale=f"Multiple severe ATT&CK techniques detected including: {technique_names}."
        )
        new_recs.append(rec)

    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="Report Generated",
        description="Final investigation summary and actionable recommendations created.",
        agent="reporter_agent",
        event_type="milestone"
    )

    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="reporter_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )

    return state.model_copy(
        update={
            "status": "completed",
            "summary": summary,
            "recommendations": state.recommendations + new_recs,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )