import asyncio
from typing import Any, Dict

from backend.app.models.casefile import (
    AgentRun,
    CaseFile,
    Entity,
    EvidenceItem,
    TimelineEvent,
    utc_now,
)


async def fetch_threat_intel(entity: Entity) -> Dict[str, Any]:
    await asyncio.sleep(0.5)

    if entity.type == "ip":
        return {
            "malicious_votes": 3,
            "country": "RU",
            "isp": "Unknown",
            "reputation": "bad",
        }
    elif entity.type == "domain":
        return {
            "creation_date": "2023-11-01",
            "threat_category": "phishing",
            "resolved_ips": ["192.168.1.5"],
        }
    elif entity.type == "user":
        return {
            "failed_logins": 12,
            "last_login": "2023-10-25T08:00:00Z",
            "department": "HR",
        }
    elif entity.type == "host":
        return {
            "os": "Windows 10",
            "missing_patches": 5,
            "edr_status": "active",
        }
    elif entity.type == "process":
        return {
            "known_malicious": False,
            "signed": True,
            "parent_process": "explorer.exe",
        }
    elif entity.type == "file":
        return {
            "hash_reputation": "unknown",
            "first_seen": None,
            "av_hits": 0,
        }
    elif entity.type == "url":
        return {
            "category": "unknown",
            "redirects_to": None,
            "threat_category": None,
        }
    elif entity.type == "email":
        return {
            "domain_reputation": "neutral",
            "spf_valid": True,
            "dmarc_valid": False,
        }
    elif entity.type == "registry":
        return {
            "known_persistence_key": False,
            "last_modified": None,
        }
    else:
        return {"info": "No additional evidence found."}


def _derive_confidence(entity: Entity, intel_data: Dict[str, Any]) -> float:
    if "error" in intel_data or intel_data.get("info") == "No additional evidence found.":
        return 0.3
    if intel_data.get("reputation") == "bad":
        return 0.95
    if intel_data.get("known_malicious") is True:
        return 0.95
    if intel_data.get("threat_category"):
        return 0.85
    return 0.7


async def evidence_agent(state: CaseFile) -> CaseFile:
    started_at = utc_now()

    try:
        # Optional rerun protection: do not append duplicate evidence if this agent already succeeded once.
        already_ran = any(
            run.agent == "evidence_agent" and run.status == "ok"
            for run in state.agent_runs
        )
        if already_ran:
            return state

        new_evidence_list = []

        tasks = [fetch_threat_intel(entity) for entity in state.entities]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        failure_count = 0

        for entity, result in zip(state.entities, results):
            if isinstance(result, Exception):
                failure_count += 1
                intel_data = {
                    "info": "Fetch failed",
                    "error": str(result),
                }
                confidence = 0.2
                tags = ["threat_intel_error", entity.type]
            else:
                intel_data = result
                confidence = _derive_confidence(entity, intel_data)

                if intel_data.get("info") == "No additional evidence found.":
                    tags = ["threat_intel", "no_info", entity.type]
                else:
                    tags = ["threat_intel", entity.type]

            evidence = EvidenceItem(
                type="intel",
                payload={
                    "entity_value": entity.value,
                    "entity_type": entity.type,
                    "intel": intel_data,
                },
                source="Threat_Intel_API",
                confidence=confidence,
                tags=tags,
            )
            new_evidence_list.append(evidence)

        finished_at = utc_now()

        if failure_count == 0:
            title = "Evidence Collection Completed"
            description = (
                f"Gathered threat intelligence for {len(state.entities)} entities."
            )
            run_status = "ok"
            run_error = None
        else:
            title = "Evidence Collection Completed with Partial Failures"
            description = (
                f"Gathered threat intelligence for {len(state.entities)} entities; "
                f"{failure_count} lookup(s) failed."
            )
            run_status = "error"
            run_error = f"{failure_count} threat intel lookup(s) failed."

        timeline_event = TimelineEvent(
            timestamp=finished_at,
            title=title,
            description=description,
            evidence_ids=[ev.id for ev in new_evidence_list],
            agent="evidence_agent",
            event_type="analysis",
        )

        agent_run = AgentRun(
            agent="evidence_agent",
            status=run_status,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=int((finished_at - started_at).total_seconds() * 1000),
            error=run_error,
        )

        return state.model_copy(
            update={
                "status": "running",
                "evidence": state.evidence + new_evidence_list,
                "timeline": state.timeline + [timeline_event],
                "agent_runs": state.agent_runs + [agent_run],
                "updated_at": finished_at,
            }
        )

    except Exception as e:
        finished_at = utc_now()

        error_event = TimelineEvent(
            timestamp=finished_at,
            title="Evidence Collection Failed",
            description=f"Evidence agent failed: {str(e)}",
            evidence_ids=[],
            agent="evidence_agent",
            event_type="analysis",
        )

        agent_run = AgentRun(
            agent="evidence_agent",
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