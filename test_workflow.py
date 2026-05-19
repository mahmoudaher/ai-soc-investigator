import asyncio
from backend.app.orchestration.graph import build_case_workflow
from backend.app.models.casefile import CaseFile
from backend.app.db.session import init_db, AsyncSessionLocal
from backend.app.db.repository import upsert_case

async def main():
    # 1. تهيئة الداتا بيز (إنشاء الجداول إذا لم تكن موجودة)
    print("[*] Initializing PostgreSQL Database Tables...")
    try:
        await init_db()
        print("[+] Database initialized successfully.")
    except Exception as e:
        print(f"[-] Database connection failed. Is your PostgreSQL server running? Error: {e}")
        return

    app = build_case_workflow()

    mock_raw_alert = {
        "title": "Suspicious repeated login failures and phishing attempt",
        "ip": "1.2.3.4",
        "user": "admin_user",
        "domain": "malicious-phishing-link.com",
        "source": "wazuh"
    }

    initial_state = CaseFile(
        case_id="TEST-DB-INTEGRATION-001",
        raw_alert=mock_raw_alert,
        status="new"
    )

    print(f"\n[*] Starting LLM workflow execution for Case: {initial_state.case_id}...")
    
    final_state = await app.ainvoke(initial_state)

    print("\n[+] Workflow execution complete! Analyzing Final CaseFile...")
    
    case_file = final_state if isinstance(final_state, CaseFile) else CaseFile(**final_state)

    # 2. حفظ الـ كيس في الداتا بيز
    print("\n[*] Saving CaseFile to PostgreSQL Database...")
    async with AsyncSessionLocal() as session:
        try:
            await upsert_case(session, case_file)
            print(f"[+] CaseFile '{case_file.case_id}' successfully saved to the database!")
        except Exception as e:
            print(f"[-] Error saving to database: {e}")

    print(f"\n[!] Case Status: {case_file.status}")

    print("\n[!] Triage AI Analysis:")
    for event in case_file.timeline:
        if event.agent == "triage_agent":
            print(f"    - {event.title}")
            print(f"      {event.description}")

    print("\n[!] Full Execution Telemetry:")
    for run in case_file.agent_runs:
        print(f"    - Agent: {run.agent:.<20} Status: {run.status:.<10} Duration: {run.duration_ms}ms")

if __name__ == "__main__":
    asyncio.run(main())