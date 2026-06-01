from datetime import datetime, timezone
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from backend.app.models.casefile import CaseFile, TimelineEvent, AgentRun
from backend.app.core.llm_config import get_llm

class TriageAnalysis(BaseModel):
    severity: str = Field(description="Alert severity level. MUST be one of: 'low', 'medium', 'high', 'critical'.")
    threat_category: str = Field(description="The general category of the alert, e.g., 'Phishing', 'Brute Force', 'Malware', 'Anomalous Traffic'.")
    confidence_score: float = Field(description="AI confidence score in this analysis, from 0.0 to 1.0.")
    reasoning: str = Field(description="A brief, professional 1-sentence technical justification for the severity and category.")

async def triage_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    
    llm = get_llm()
    structured_llm = llm.with_structured_output(TriageAnalysis)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an elite Level 1 SOC Triage Analyst. 
        Your task is to analyze raw security alerts (Payload) and classify them strictly according to the requested schema.
        Do not hallucinate. Base your entire analysis ONLY on the provided alert payload."""),
        ("human", "Analyze the following raw alert data:\n\n{alert_payload}")
    ])
    
    chain = prompt | structured_llm
    
    analysis_result = await chain.ainvoke({"alert_payload": str(state.raw_alert)})
    
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="AI Triage Analysis Complete",
        description=f"Alert categorized as {analysis_result.threat_category} ({analysis_result.severity} severity). AI Reasoning: {analysis_result.reasoning}",
        agent="triage_agent",
        event_type="analysis"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="triage_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "status": "running",
            "updated_at": finished_at,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )