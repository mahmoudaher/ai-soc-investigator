from langgraph.graph import END, StateGraph

from backend.app.agents.triage import triage_agent
from backend.app.agents.recon import recon_agent
from backend.app.agents.mapper import mapper_agent
from backend.app.agents.evidence import evidence_agent
from backend.app.agents.reporter import reporter_agent
from backend.app.agents.finalizer import finalizer_node
from backend.app.models.casefile import CaseFile

def build_case_workflow():
    workflow = StateGraph(CaseFile)

    workflow.add_node("triage", triage_agent)
    workflow.add_node("evidence", evidence_agent)
    workflow.add_node("recon", recon_agent)
    workflow.add_node("mapper", mapper_agent)
    workflow.add_node("reporter", reporter_agent)
    workflow.add_node("finalizer", finalizer_node)
    
    workflow.set_entry_point("triage")

    workflow.add_edge("triage", "evidence")
    workflow.add_edge("evidence", "recon")
    workflow.add_edge("recon", "mapper")
    workflow.add_edge("mapper", "reporter")
    workflow.add_edge("reporter", "finalizer")
    workflow.add_edge("finalizer", END)

    return workflow.compile()

def get_case_workflow_mermaid() -> str:
    return build_case_workflow().get_graph().draw_mermaid()