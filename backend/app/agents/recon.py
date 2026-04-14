from ipaddress import ip_address

from backend.app.models.casefile import AgentRun, CaseFile, EvidenceItem, TimelineEvent, utc_now


def _is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


async def recon_agent(state: CaseFile) -> CaseFile:
    started_at = utc_now()
    triage = state.triage
    recon_evidence = []

    if triage:
        for step in triage.plan:
            finding = {
                "goal": step.goal,
                "rationale": step.rationale,
                "entity_type": step.entity_type,
                "entity_value": step.entity_value,
                "validation": "no_action",
            }

            if step.entity_type == "ip" and step.entity_value:
                finding["validation"] = "private_ip" if _is_private_ip(step.entity_value) else "public_ip"
            elif step.entity_type == "host" and step.entity_value:
                hostname = step.entity_value.lower()
                if any(marker in hostname for marker in ("lab", "test", "dev", "sandbox")):
                    finding["validation"] = "lab_host"
                else:
                    finding["validation"] = "host_observed"
            elif step.entity_type == "domain" and step.entity_value:
                finding["validation"] = "domain_observed"
            elif step.entity_type == "user" and step.entity_value:
                finding["validation"] = "user_observed"
            elif step.entity_type == "process" and step.entity_value:
                finding["validation"] = "process_observed"

            recon_evidence.append(
                EvidenceItem(
                    type="note",
                    payload=finding,
                    source="recon_agent",
                    confidence=0.8,
                    tags=["recon", step.entity_type or "unknown"],
                )
            )

    timeline_event = TimelineEvent(
        timestamp=utc_now(),
        title="Reconnaissance Completed",
        description=f"Validated {len(recon_evidence)} triage plan items for follow-up investigation.",
        evidence_ids=[item.id for item in recon_evidence],
        agent="recon_agent",
        event_type="analysis",
    )

    finished_at = utc_now()
    agent_run = AgentRun(
        agent="recon_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000),
    )

    return state.model_copy(
        update={
            "status": "running",
            "evidence": state.evidence + recon_evidence,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run],
            "updated_at": finished_at,
        }
    )
