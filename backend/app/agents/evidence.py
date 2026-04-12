import asyncio
from datetime import datetime, timezone
from typing import Dict, Any
from backend.app.models.casefile import AgentRun, CaseFile, Entity, TimelineEvent, EvidenceItem 


async def fetch_threat_intel(entity: Entity) -> Dict[str, Any]:# in the future Siem tools , edr , ids or ip/domain reputation could be used to retrieve valube information about the entity
    await asyncio.sleep(0.5)  
    
    if entity.type == "ip":
        return {"malicious_votes": 3, "country": "RU", "isp": "Unknown", "reputation": "bad"}
    elif entity.type == "domain":
        return {"creation_date": "2023-11-01", "threat_category": "phishing", "resolved_ips": ["192.168.1.5"]}
    elif entity.type == "user":
        return {"failed_logins": 12, "last_login": "2023-10-25T08:00:00Z", "department": "HR"}
    elif entity.type == "host":
        return {"os": "Windows 10", "missing_patches": 5, "edr_status": "active"}
    else:
        return {"info": "No additional evidence found."}


async def evidence_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    new_evidence_list = []
    
    tasks = [fetch_threat_intel(entity) for entity in state.entities]
    results = await asyncio.gather(*tasks)
    
    for entity, intel_data in zip(state.entities, results):
        evidence = EvidenceItem(
            type="intel",
            payload={
            "entity_value": entity.value,
            "entity_type": entity.type,
            "intel": intel_data
        },
        source="Threat_Intel_API",
        confidence=0.85,
        tags=["threat_intel", entity.type]
    )
        new_evidence_list.append(evidence)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="Evidence Collection Completed",
        description=f"Gathered threat intelligence for {len(state.entities)} entities.",
        evidence_ids=[ev.id for ev in new_evidence_list], 
        agent="evidence_agent",
        event_type="analysis"
    )

    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="evidence_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000),
    )
    
   
    updated_state = state.model_copy(update={
        "status": "running",
        "evidence": getattr(state, 'evidence', []) + new_evidence_list,
        "timeline": state.timeline + [timeline_event],
        "agent_runs": state.agent_runs + [agent_run],
    })
    
    return updated_state
