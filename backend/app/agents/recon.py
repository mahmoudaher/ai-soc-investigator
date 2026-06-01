import os
import httpx
import asyncio
from datetime import datetime, timezone
from backend.app.models.casefile import CaseFile, TimelineEvent, AgentRun

async def check_virustotal(observable_type: str, observable_value: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    
    if observable_type == "ip":
        url = f"{base_url}/ip_addresses/{observable_value}"
    elif observable_type == "domain":
        url = f"{base_url}/domains/{observable_value}"
    else:
        return {"reputation": "Unknown", "details": "Type not supported for VT lookup."}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0:
                    reputation = "Malicious"
                elif suspicious > 0:
                    reputation = "Suspicious"
                else:
                    reputation = "Clean"
                    
                details = f"VT Stats: {malicious} malicious, {suspicious} suspicious out of total scans."
                return {"reputation": reputation, "details": details}
            elif response.status_code == 404:
                return {"reputation": "Unknown", "details": "Not found in VirusTotal database."}
            else:
                return {"reputation": "Error", "details": f"VT API returned status {response.status_code}"}
        except Exception as e:
            return {"reputation": "Error", "details": str(e)}

async def recon_agent(state: CaseFile) -> CaseFile:
    started_at = datetime.now(timezone.utc)
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not state.evidence or not api_key:
        finished_at = datetime.now(timezone.utc)
        agent_run = AgentRun(
            agent="recon_agent",
            status="error" if not api_key else "ok",
            error="VIRUSTOTAL_API_KEY missing" if not api_key else None,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=0
        )
        return state.model_copy(
            update={
                "updated_at": finished_at,
                "agent_runs": state.agent_runs + [agent_run]
            }
        )

    updated_evidence = []
    enriched_count = 0
    
    for idx, ev in enumerate(state.evidence):
        ev_copy = ev.model_copy()
        val = ev.payload.get("value")
        
        vt_type = None
        all_types = [ev.type.lower()] + [tag.lower() for tag in ev.tags]
        
        if any("ip" in t for t in all_types):
            vt_type = "ip"
        elif any("domain" in t or "url" in t for t in all_types):
            vt_type = "domain"
        
        if val and vt_type:
            if enriched_count > 0:
                await asyncio.sleep(16)
                
            vt_result = await check_virustotal(vt_type, val, api_key)
            ev_copy.payload["reputation"] = vt_result["reputation"]
            ev_copy.payload["intel_details"] = vt_result["details"]
            enriched_count += 1
        else:
            ev_copy.payload["reputation"] = "N/A"
            ev_copy.payload["intel_details"] = "No external intel required."
            
        updated_evidence.append(ev_copy)
        
    timeline_event = TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        title="Real-time Threat Intel Lookup",
        description=f"Successfully queried VirusTotal for {enriched_count} artifacts.",
        agent="recon_agent",
        event_type="analysis"
    )
    
    finished_at = datetime.now(timezone.utc)
    agent_run = AgentRun(
        agent="recon_agent",
        status="ok",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=int((finished_at - started_at).total_seconds() * 1000)
    )
    
    return state.model_copy(
        update={
            "evidence": updated_evidence,
            "updated_at": finished_at,
            "timeline": state.timeline + [timeline_event],
            "agent_runs": state.agent_runs + [agent_run]
        }
    )