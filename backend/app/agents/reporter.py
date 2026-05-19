from datetime import datetime, timezone
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from backend.app.models.casefile import CaseFile, TimelineEvent, AgentRun
from backend.app.core.llm_config import get_llm

class InvestigationReport(BaseModel):
    summary: str = Field(description="A professional, high-level executive summary of the investigation findings.")
    recommendations: str = Field(description="Bullet-pointed actionable defense and remediation recommendations for SOC analysts.")

async def reporter_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    
    llm = get_llm()
    structured_llm = llm.with_structured_output(InvestigationReport)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert Cyber Security Incident Responder and Reporting Specialist.
        Your task is to review the complete CaseFile, including triage decisions, extracted evidence, and MITRE ATT&CK mappings.
        Generate a comprehensive, professional technical summary and clear recommendations for containment and mitigation."""),
        ("human", """Analyze the completed case file investigation:
        
        Alert Context: {alert_context}
        Evidence Items: {evidence_data}
        MITRE Techniques: {mitre_data}""")
    ])
    
    chain = prompt | structured_llm
    
    evidence_summary = "\n".join([f"- Type: {ev.type}, Tags: {ev.tags}, Data: {ev.payload}" for ev in state.evidence])
    mitre_summary = "\n".join([f"- [{t.technique_id}] {t.name} (Tactic: {t.tactic})" for t in state.mitre])
    
    report_result = await chain.ainvoke({
        "alert_context": str(state.raw_alert),
        "evidence_data": evidence_summary,
        "mitre_data": mitre_summary
    })
    
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="AI Final Incident Report Generated",
        description="The reporter agent has finalized the case analysis and attached defense recommendations.",
        agent="reporter_agent",
        event_type="milestone"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="reporter_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "status": "completed",
            "summary": f"{report_result.summary}\n\nRecommendations:\n{report_result.recommendations}",
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )