from datetime import datetime, timezone
from backend.app.models.casefile import CaseFile, MitreTechnique, TimelineEvent, AgentRun

async def ttp_mapper_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    new_mitre_techniques = []

    for evidence in state.evidence:
        payload = evidence.payload
        
        if evidence.tags and "domain" in evidence.tags:
            if payload.get("intel", {}).get("threat_category") == "phishing":
                tech = MitreTechnique(
                    technique_id="T1566",
                    name="Phishing",
                    confidence=0.9,
                    evidence_ids=[evidence.id],
                    reason="Detected known phishing domain in Threat Intel data.",
                    tactic="Initial Access"
                )
                new_mitre_techniques.append(tech)
        
        if evidence.tags and "user" in evidence.tags:
            if payload.get("intel", {}).get("failed_logins", 0) > 10:
                tech = MitreTechnique(
                    technique_id="T1110",
                    name="Brute Force",
                    confidence=0.85,
                    evidence_ids=[evidence.id],
                    reason="Observed multiple failed login attempts exceeding standard threshold.",
                    tactic="Credential Access"
                )
                new_mitre_techniques.append(tech)

    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="TTP Mapping Completed",
        description=f"Mapped {len(new_mitre_techniques)} MITRE ATT&CK techniques based on heuristic analysis.",
        evidence_ids=[], 
        agent="ttp_mapper_agent",
        event_type="analysis"
    )

    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="ttp_mapper_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )

    return state.model_copy(
        update={
            "status": "running",
            "mitre": state.mitre + new_mitre_techniques,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )