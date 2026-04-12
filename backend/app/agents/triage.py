from datetime import datetime, timezone

from backend.app.models.casefile import (
    AgentRun,
    CaseFile,
    Entity,
    TimelineEvent,
    TriageAssessment,
    TriagePlanStep,
)


async def triage_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    alert = state.raw_alert

    new_entities = []


    if ip := alert.get("ip"):
        new_entities.append(Entity(type="ip", value=ip))

    if user := alert.get("user"):
        new_entities.append(Entity(type="user", value=user))

    if host := alert.get("host"):
        new_entities.append(Entity(type="host", value=host))

    # Extract additional entities
    if domain := alert.get("domain"):
        new_entities.append(Entity(type="domain", value=domain))

    if process := alert.get("process"):
        new_entities.append(Entity(type="process", value=process))


    title = alert.get("title", "").lower()

    if "phishing" in title:
        category = "phishing"
        severity = "high"
    elif "login" in title or "auth" in title:
        category = "credential"
        severity = "medium"
    elif "malware" in title or "virus" in title:
        category = "malware"
        severity = "critical"
    elif "ddos" in title or "flood" in title:
        category = "denial_of_service"
        severity = "high"
    else:
        category = "network_anomaly"
        severity = "low"

    plan = []
    for entity in new_entities:
        if entity.type in {"ip", "host", "domain", "user", "process"}:
            plan.append(
                TriagePlanStep(
                    entity_type=entity.type,
                    entity_value=entity.value,
                    goal=f"Validate whether {entity.type} '{entity.value}' is relevant to the alert.",
                    rationale=f"Triage extracted {entity.type} from the incoming alert and recon should confirm its significance.",
                    priority=severity,
                )
            )

    triage_assessment = TriageAssessment(
        summary=f"Classified alert as {category} with {severity} severity based on title heuristics and extracted entities.",
        confidence=0.7,
        plan=plan,
    )

    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="Pre-Triage Completed",
        description="Initial triage completed based on heuristic rules.",
        evidence_ids=[],
        agent="triage_agent",
        event_type="analysis"
    )

    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="triage_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000),
    )

    updated_state = state.model_copy(update={
        "severity": severity,
        "category": category,
        "status": "running",
        "triage": triage_assessment,
        "entities": state.entities + new_entities,
        "timeline": state.timeline + [timeline_event],
        "agent_runs": state.agent_runs + [agent_run],
    })

    return updated_state
