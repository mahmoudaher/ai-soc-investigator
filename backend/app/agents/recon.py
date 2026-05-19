from datetime import datetime, timezone
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from backend.app.models.casefile import CaseFile, TimelineEvent, AgentRun
from backend.app.core.llm_config import get_llm

class ReconArtifact(BaseModel):
    value: str = Field(description="The evidence value examined, e.g., '1.2.3.4'")
    reputation: str = Field(description="Simulated reputation score or status, e.g., 'Malicious', 'Suspicious', 'Clean'")
    details: str = Field(description="1-sentence threat intelligence context for this artifact.")

class ReconReport(BaseModel):
    results: list[ReconArtifact]

async def recon_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    
    if not state.evidence:
        finished_at = datetime.now(timezone.utc)
        agent_run = AgentRun(
            agent="recon_agent",
            status="ok",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=0
        )
        return state.model_copy(update={"agent_runs": state.agent_runs + [agent_run]})

    llm = get_llm()
    structured_llm = llm.with_structured_output(ReconReport)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert Threat Intelligence Enrichment Agent.
        Your job is to analyze the provided evidence artifacts and provide a simulated threat intelligence lookup.
        Determine if the artifact is Malicious, Suspicious, or Clean, and provide short contextual details."""),
        ("human", "Artifacts to enrich:\n{artifacts}")
    ])
    
    chain = prompt | structured_llm
    
    artifacts_input = "\n".join([f"- Type: {ev.type}, Value: {ev.payload.get('value', 'unknown')}" for ev in state.evidence])
    
    recon_result = await chain.ainvoke({"artifacts": artifacts_input})
    
    updated_evidence = []
    for ev in state.evidence:
        ev_copy = ev.model_copy()
        for res in recon_result.results:
            if res.value == ev.payload.get("value"):
                ev_copy.payload["reputation"] = res.reputation
                ev_copy.payload["intel_details"] = res.details
        updated_evidence.append(ev_copy)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="AI Threat Intelligence Enrichment Complete",
        description=f"Enriched {len(updated_evidence)} artifacts with simulated threat intelligence data.",
        agent="recon_agent",
        event_type="analysis"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="recon_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "evidence": updated_evidence,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )