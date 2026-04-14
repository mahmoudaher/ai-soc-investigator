from langgraph.graph import END, StateGraph

from backend.app.agents.evidence import evidence_agent
from backend.app.agents.triage import triage_agent
from backend.app.agents.recon import recon_agent
from backend.app.models.casefile import CaseFile


def build_case_workflow():
    workflow = StateGraph(CaseFile)
    workflow.add_node("triage", triage_agent)
    workflow.add_node("evidence", evidence_agent)
    workflow.add_node("reconnaissance", recon_agent)
    workflow.set_entry_point("triage")
    workflow.add_edge("triage", "evidence")
    workflow.add_edge("evidence", "reconnaissance")
    workflow.add_edge("reconnaissance", END)
    return workflow.compile()


def get_case_workflow_mermaid() -> str:
    return build_case_workflow().get_graph().draw_mermaid()
