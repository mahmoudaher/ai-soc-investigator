import asyncio
from backend.app.orchestration.graph import build_case_workflow
from backend.app.models.casefile import CaseFile

async def main():
    app = build_case_workflow()

    mock_raw_alert = {
        "title": "Suspicious repeated login failures and phishing attempt",
        "ip": "1.2.3.4",
        "user": "admin_user",
        "domain": "malicious-phishing-link.com",
        "source": "wazuh"
    }

    initial_state = CaseFile(
        case_id="TEST-LLM-TRIAGE-003",
        raw_alert=mock_raw_alert,
        status="new"
    )

    print(f"[*] Starting LLM workflow execution for Case: {initial_state.case_id}...")
    
    final_state = await app.ainvoke(initial_state)

    print("\n[+] Workflow execution complete! Analyzing Final CaseFile...")
    
    case_file = final_state if isinstance(final_state, CaseFile) else CaseFile(**final_state)

    print(f"\n[!] Case Status: {case_file.status}")

    print("\n[!] Triage AI Analysis:")
    for event in case_file.timeline:
        if event.agent == "triage_agent":
            print(f"    - {event.title}")
            print(f"      {event.description}")

    print(f"\n[!] Investigation Summary:\n    {case_file.summary}")

    print(f"\n[!] MITRE ATT&CK Techniques Mapped ({len(case_file.mitre)}):")
    for tech in case_file.mitre:
        print(f"    - [{tech.technique_id}] {tech.name} (Tactic: {tech.tactic})")

    print("\n[!] Full Execution Telemetry:")
    for run in case_file.agent_runs:
        print(f"    - Agent: {run.agent:.<20} Status: {run.status:.<10} Duration: {run.duration_ms}ms")

if __name__ == "__main__":
    asyncio.run(main())