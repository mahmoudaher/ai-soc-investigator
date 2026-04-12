from langgraph.graph import END, StateGraph

from backend.app.agents.evidence import evidence_agent
from backend.app.agents.triage import triage_agent
from backend.app.models.casefile import CaseFile


def build_case_workflow():
    workflow = StateGraph(CaseFile)
    workflow.add_node("triage", triage_agent)
    workflow.add_node("evidence", evidence_agent)
    workflow.add_node("reconnaissance", reconnaissance_agent)
    workflow.add_node("ttp_mapper", ttp_mapper_agent)
    workflow.add_node("reporter", reporter_agent)
    workflow.set_entry_point("triage")
    workflow.add_edge("triage", "evidence")
    workflow.add_edge("evidence", "reconnaissance")
    workflow.add_edge("reconnaissance", "ttp_mapper")
    workflow.add_edge("ttp_mapper", "reporter")
    workflow.add_edge("reporter", END)
    return workflow.compile()
