import asyncio
import json
from langgraph.graph import StateGraph, END


from backend.app.models.casefile import CaseFile 
from backend.app.agents.triage import triage_agent 

async def main():
    
    workflow = StateGraph(CaseFile)

    
    workflow.add_node("triage", triage_agent)

    
    workflow.set_entry_point("triage")
    workflow.add_edge("triage", END)

    
    app = workflow.compile()

    
    mock_raw_alert = {
        "title": "Suspicious repeated login failures",
        "ip": "192.168.1.105",
        "user": "service_account",
        "source": "wazuh"
    }

    
    initial_state = CaseFile(
        case_id="TEST-CASE-001",
        raw_alert=mock_raw_alert,
        status="new"
    )

    print(f"[*] Starting test for Case: {initial_state.case_id}...")
    

    final_state = await app.ainvoke(initial_state)

    
    print("\n[+] Graph execution complete! Final Case File State:\n")
    
    case_file = CaseFile(**final_state)
    print(case_file.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())