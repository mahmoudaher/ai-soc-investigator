import requests
import json

URL = "http://localhost:8000/alerts/wazuh"

wazuh_alert = {
    "timestamp": "2026-05-21T14:42:38.123+0300",
    "rule": {
        "level": 10,
        "description": "SQL Injection attempt detected",
        "id": "5712",
        "groups": ["syslog", "sshd", "authentication_failures"]
    },
    "agent": {
        "id": "001",
        "name": "linux-prod-server",
        "ip": "192.168.1.50"
    },
    "data": {
        "srcip": "8.8.8.8",  
        "srcuser": "root",
        "srcport": "45231"
    },
    "decoder": {"name": "sshd"},
    "full_log": "Failed password for root from 185.153.196.22 port 45231 ssh2"
}

print("[*] Sending simulated Wazuh Alert to AI SOC Investigator...")

try:
    response = requests.post(URL, json=wazuh_alert)
    
    print(f"[+] Status Code: {response.status_code}")
    print("[+] Response Data:")
    print(json.dumps(response.json(), indent=2))
    print("\n[!] The alert was ingested successfully. The AI pipeline is now running in the background!")
except Exception as e:
    print(f"[-] Connection failed. Is the FastAPI server running? Error: {e}")