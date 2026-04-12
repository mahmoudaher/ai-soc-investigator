import asyncio
import json
from langgraph.graph import StateGraph, END

from backend.app.models.casefile import CaseFile 
from backend.app.agents.triage import triage_agent 
from backend.app.agents.evidence import evidence_agent 

async def main():
    workflow = StateGraph(CaseFile)

    workflow.add_node("triage", triage_agent)
    workflow.add_node("evidence", evidence_agent)

    workflow.set_entry_point("triage")
    
    workflow.add_edge("triage", "evidence")
    workflow.add_edge("evidence", END)

    app = workflow.compile()

    mock_raw_alert = {
        "title": "Suspicious repeated login failures from unknown IP",
        "ip": "192.168.1.105",
        "user": "service_account",
        "domain": "malicious-site.com",
        "source": "wazuh"
    }

    initial_state = CaseFile(
        case_id="TEST-CASE-001",
        raw_alert=mock_raw_alert,
        status="new"
    )

    print(f"[*] Starting test for Case: {initial_state.case_id}...")
    print("[*] Flow: Entry -> Triage -> Evidence -> END\n")

    final_state = await app.ainvoke(initial_state)

    print("\n[+] Graph execution complete! Final Case File State:\n")
    
    if isinstance(final_state, CaseFile):
        case_file = final_state
    else:
        case_file = CaseFile(**final_state)
    print(case_file.model_dump_json(indent=2))

if __name__ == "__main__":
    asyncio.run(main())