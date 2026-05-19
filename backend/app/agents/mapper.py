from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from backend.app.models.casefile import CaseFile, MitreTechnique, TimelineEvent, AgentRun
from backend.app.core.llm_config import get_llm

class ExtractedMitreTechnique(BaseModel):
    technique_id: str = Field(description="The MITRE ATT&CK technique ID, e.g., 'T1110', 'T1566'")
    name: str = Field(description="The standard name of the technique")
    tactic: str = Field(description="The associated overarching tactic, e.g., 'Credential Access', 'Initial Access'")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    reason: str = Field(description="1-sentence technical justification for mapping this technique")

class MitreMappingList(BaseModel):
    mappings: List[ExtractedMitreTechnique]

async def mapper_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    
    if not state.evidence:
        finished_at = datetime.now(timezone.utc)
        agent_run = AgentRun(
            agent="mapper_agent",
            status="ok",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=0
        )
        return state.model_copy(update={"agent_runs": state.agent_runs + [agent_run]})

    llm = get_llm()
    structured_llm = llm.with_structured_output(MitreMappingList)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert Cyber Threat Intelligence Analyst.
        Your job is to analyze extracted case evidence and raw alert context, then map them to official MITRE ATT&CK techniques.
        Provide accurate IDs, tactics, names, and a high-quality technical justification."""),
        ("human", "Alert Context: {alert_context}\n\nExtracted Evidence Artifacts: {evidence_data}")
    ])
    
    chain = prompt | structured_llm
    
    evidence_summary = "\n".join([f"- Type: {ev.type}, Data: {ev.payload}" for ev in state.evidence])
    
    mapping_result = await chain.ainvoke({
        "alert_context": str(state.raw_alert),
        "evidence_data": evidence_summary
    })
    
    all_evidence_ids = [ev.id for ev in state.evidence]
    
    new_mitre_techniques = []
    for mapping in mapping_result.mappings:
        tech = MitreTechnique(
            technique_id=mapping.technique_id,
            name=mapping.name,
            tactic=mapping.tactic,
            confidence=mapping.confidence,
            reason=mapping.reason,
            evidence_ids=all_evidence_ids
        )
        new_mitre_techniques.append(tech)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="AI MITRE ATT&CK Mapping Complete",
        description=f"Successfully mapped {len(new_mitre_techniques)} ATT&CK techniques based on automated evidence analysis.",
        agent="mapper_agent",
        event_type="analysis"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="mapper_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "mitre": state.mitre + new_mitre_techniques,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )