from datetime import datetime
from backend.app.models.casefile import CaseFile, Entity, TimelineEvent


async def triage_agent(state: CaseFile) -> CaseFile:
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


    timeline_event = TimelineEvent(
        timestamp=datetime.utcnow(),
        title="Pre-Triage Completed",
        description="Initial triage completed based on heuristic rules.",
        evidence_ids=[],
        agent="triage_agent",
        event_type="analysis"
    )


    updated_state = state.model_copy(update={
        "severity": severity,
        "category": category,
        "status": "running",
        "entities": state.entities + new_entities,
        "timeline": state.timeline + [timeline_event]
    })

    return updated_state