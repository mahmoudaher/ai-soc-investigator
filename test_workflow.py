import asyncio
import json
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
        case_id="TEST-FULL-FLOW-001",
        raw_alert=mock_raw_alert,
        status="new"
    )

    print(f"[*] Starting full workflow execution for Case: {initial_state.case_id}...")
    
    final_state = await app.ainvoke(initial_state)

    print("\n[+] Workflow execution complete! Analyzing Results...")
    
    case_file = final_state if isinstance(final_state, CaseFile) else CaseFile(**final_state)

    print(f"\n[!] MITRE ATT&CK Techniques Mapped: {len(case_file.mitre)}")
    for tech in case_file.mitre:
        print(f"    - [{tech.technique_id}] {tech.name} (Tactic: {tech.tactic}) | Confidence: {tech.confidence}")
        print(f"      Reason: {tech.reason}")

    print("\n[!] Execution Telemetry:")
    for run in case_file.agent_runs:
        print(f"    - Agent: {run.agent:.<20} Status: {run.status:.<10} Duration: {run.duration_ms}ms")

if __name__ == "__main__":
    asyncio.run(main())