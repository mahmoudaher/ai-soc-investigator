import uuid
from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from backend.app.models.casefile import CaseFile, EvidenceItem, TimelineEvent, AgentRun
from backend.app.core.llm_config import get_llm

class ExtractedEvidence(BaseModel):
    evidence_type: str = Field(description="MUST be one of: 'ip', 'domain', 'user', 'hash', 'url'")
    value: str = Field(description="The actual value extracted")
    description: str = Field(description="Brief explanation of this evidence")

class EvidenceExtractionList(BaseModel):
    items: List[ExtractedEvidence]

async def evidence_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    
    llm = get_llm()
    structured_llm = llm.with_structured_output(EvidenceExtractionList)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a highly skilled SOC Evidence Extraction Agent.
        Analyze the raw payload and extract all technical artifacts (IPs, domains, users, etc.).
        Return them strictly according to the schema."""),
        ("human", "{payload}")
    ])
    
    chain = prompt | structured_llm
    
    extraction_result = await chain.ainvoke({"payload": str(state.raw_alert)})
    
    new_evidence_items = []
    for item in extraction_result.items:
        ev = EvidenceItem(
            id=str(uuid.uuid4()),
            type="intel",
            source="llm_extractor",
            tags=["extracted_by_ai", item.evidence_type],
            payload={
                "value": item.value,
                "description": item.description
            }
        )
        new_evidence_items.append(ev)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="AI Evidence Extraction Complete",
        description=f"Successfully extracted {len(new_evidence_items)} artifacts using AI.",
        agent="evidence_agent",
        event_type="analysis"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="evidence_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "evidence": state.evidence + new_evidence_items,
            "updated_at": finished_at,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )