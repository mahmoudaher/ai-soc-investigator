import asyncio
from datetime import datetime
from typing import Dict, Any
from backend.app.models.casefile import CaseFile, Entity, TimelineEvent, Evidence


async def fetch_threat_intel(entity: Entity) -> Dict[str, Any]:
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
    new_evidence_list = []
    
    tasks = [fetch_threat_intel(entity) for entity in state.entities]
    results = await asyncio.gather(*tasks)
    
    for entity, intel_data in zip(state.entities, results):
        evidence = Evidence(
            entity_value=entity.value,
            entity_type=entity.type,
            source="Threat_Intel_API",
            data=intel_data,
            collected_at=datetime.utcnow()
        )
        new_evidence_list.append(evidence)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.utcnow(),
        title="Evidence Collection Completed",
        description=f"Gathered threat intelligence for {len(state.entities)} entities.",
        evidence_ids=[], 
        agent="evidence_agent",
        event_type="investigation"
    )
    
   
    updated_state = state.model_copy(update={
        "status": "investigating",
        "evidences": getattr(state, 'evidences', []) + new_evidence_list,
        "timeline": state.timeline + [timeline_event]
    })
    
    return updated_state