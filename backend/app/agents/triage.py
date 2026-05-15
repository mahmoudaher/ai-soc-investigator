from backend.app.models.casefile import (
    AgentRun,
    CaseFile,
    Entity,
    TimelineEvent,
    TriageAssessment,
    TriagePlanStep,
    utc_now,
)


async def triage_agent(state: CaseFile) -> CaseFile:
    started_at = utc_now()

    try:
        alert = state.raw_alert
        new_entities = []

        if ip := alert.get("ip"):
            new_entities.append(Entity(type="ip", value=ip))

        if user := alert.get("user"):
            new_entities.append(Entity(type="user", value=user))

        if host := alert.get("host"):
            new_entities.append(Entity(type="host", value=host))

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

        # Deduplicate against existing entities
        existing = {(e.type, e.value) for e in state.entities}
        deduped_new = []
        seen_new = set()

        for entity in new_entities:
            key = (entity.type, entity.value)
            if key not in existing and key not in seen_new:
                deduped_new.append(entity)
                seen_new.add(key)

        # Build plan only from newly added unique entities
        plan = []
        for entity in deduped_new:
            plan.append(
                TriagePlanStep(
                    entity_type=entity.type,
                    entity_value=entity.value,
                    goal=f"Validate whether {entity.type} '{entity.value}' is relevant to the alert.",
                    rationale=(
                        f"Triage extracted {entity.type} from the incoming alert "
                        f"and recon should confirm its significance."
                    ),
                    priority=severity,
                )
            )

        triage_assessment = TriageAssessment(
            summary=(
                f"Classified alert as {category} with {severity} severity "
                f"based on title heuristics and extracted entities."
            ),
            confidence=0.7,
            plan=plan,
        )

        timeline_event = TimelineEvent(
            timestamp=utc_now(),
            title="Pre-Triage Completed",
            description="Initial triage completed based on heuristic rules.",
            evidence_ids=[],
            agent="triage_agent",
            event_type="analysis",
        )

        finished_at = utc_now()
        agent_run = AgentRun(
            agent="triage_agent",
            status="ok",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=int((finished_at - started_at).total_seconds() * 1000),
        )

        return state.model_copy(
            update={
                "severity": severity,
                "category": category,
                "status": "running",
                "priority": severity,  # same value set, since literals match
                "triage": triage_assessment,
                "entities": state.entities + deduped_new,
                "timeline": state.timeline + [timeline_event],
                "agent_runs": state.agent_runs + [agent_run],
                "updated_at": finished_at,
            }
        )

    except Exception as e:
        finished_at = utc_now()

        error_event = TimelineEvent(
            timestamp=finished_at,
            title="Pre-Triage Failed",
            description=f"Triage failed: {str(e)}",
            evidence_ids=[],
            agent="triage_agent",
            event_type="analysis",
        )

        agent_run = AgentRun(
            agent="triage_agent",
            status="error",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=int((finished_at - started_at).total_seconds() * 1000),
            error=str(e),
        )

        return state.model_copy(
            update={
                "status": "failed",
                "timeline": state.timeline + [error_event],
                "agent_runs": state.agent_runs + [agent_run],
                "updated_at": finished_at,
            }
        )