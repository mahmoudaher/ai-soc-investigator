import json
from pathlib import Path
import unittest

from backend.app.normalization.wazuh import normalize_wazuh_alert


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "wazuh"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class WazuhNormalizationTests(unittest.TestCase):
    def test_normalizes_linux_auth_alert(self):
        raw_alert = {
            "timestamp": "2026-05-16T10:15:30.123+0000",
            "rule": {
                "level": 7,
                "description": "sshd: authentication failed.",
                "id": "5716",
                "groups": ["syslog", "sshd", "authentication_failed"],
            },
            "agent": {
                "id": "002",
                "name": "ubuntu-victim",
                "ip": "192.168.56.20",
            },
            "id": "1778936130.123456",
            "full_log": "Failed password for admin from 10.0.2.15 port 53322 ssh2",
            "decoder": {"name": "sshd"},
            "data": {
                "srcip": "10.0.2.15",
                "srcuser": "admin",
                "srcport": "53322",
            },
            "location": "/var/log/auth.log",
        }

        normalized = normalize_wazuh_alert(raw_alert)

        self.assertEqual(normalized["source"], "wazuh")
        self.assertEqual(normalized["title"], "sshd: authentication failed.")
        self.assertEqual(normalized["source_alert_id"], "1778936130.123456")
        self.assertEqual(normalized["rule_id"], "5716")
        self.assertEqual(normalized["rule_level"], 7)
        self.assertEqual(normalized["host"], "ubuntu-victim")
        self.assertEqual(normalized["agent_id"], "002")
        self.assertEqual(normalized["agent_ip"], "192.168.56.20")
        self.assertEqual(normalized["ip"], "10.0.2.15")
        self.assertEqual(normalized["user"], "admin")
        self.assertEqual(normalized["decoder"], "sshd")
        self.assertEqual(normalized["wazuh"], raw_alert)

    def test_normalizes_windows_event_fields(self):
        raw_alert = {
            "rule": {"description": "Windows logon failure", "level": 5},
            "agent": {"name": "win-endpoint-01"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "jane",
                        "ipAddress": "172.16.1.20",
                        "processName": "C:\\Windows\\System32\\svchost.exe",
                    }
                }
            },
        }

        normalized = normalize_wazuh_alert(raw_alert)

        self.assertEqual(normalized["host"], "win-endpoint-01")
        self.assertEqual(normalized["ip"], "172.16.1.20")
        self.assertEqual(normalized["source_ip"], "172.16.1.20")
        self.assertEqual(normalized["user"], "jane")
        self.assertEqual(
            normalized["process"],
            "C:\\Windows\\System32\\svchost.exe",
        )

    def test_classifies_windows_failed_login_fixture(self):
        normalized = normalize_wazuh_alert(load_fixture("windows_failed_login.json"))

        self.assertEqual(normalized["event_kind"], "authentication")
        self.assertEqual(normalized["event_action"], "failed_login")
        self.assertEqual(normalized["windows_event_id"], "4625")
        self.assertEqual(normalized["windows_provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(normalized["windows_channel"], "Security")
        self.assertEqual(normalized["windows_computer"], "Ahmed-364")
        self.assertEqual(normalized["user"], "Administrator")
        self.assertEqual(normalized["domain"], "AHMED-364")
        self.assertEqual(normalized["source_ip"], "::1")
        self.assertEqual(normalized["source_port"], "0")
        self.assertEqual(normalized["logon_type"], "2")
        self.assertEqual(normalized["authentication_package"], "Negotiate")
        self.assertEqual(normalized["failure_status"], "0xc000006d")
        self.assertEqual(normalized["process"], "C:\\\\Windows\\\\System32\\\\svchost.exe")

    def test_classifies_windows_service_config_change_fixture(self):
        normalized = normalize_wazuh_alert(
            load_fixture("windows_service_config_change.json")
        )

        self.assertEqual(normalized["event_kind"], "configuration")
        self.assertEqual(normalized["event_action"], "service_config_change")
        self.assertEqual(normalized["windows_event_id"], "7040")
        self.assertEqual(normalized["windows_provider"], "Service Control Manager")
        self.assertEqual(normalized["service_name"], "OpenSSH SSH Server")
        self.assertEqual(normalized["service_start_type"], "auto start")

    def test_classifies_windows_new_service_fixture(self):
        normalized = normalize_wazuh_alert(
            load_fixture("windows_new_service_created.json")
        )

        self.assertEqual(normalized["event_kind"], "configuration")
        self.assertEqual(normalized["event_action"], "new_service_created")
        self.assertEqual(normalized["windows_event_id"], "7045")
        self.assertEqual(normalized["service_name"], "Sysmon")
        self.assertEqual(normalized["service_image"], "C:\\\\WINDOWS\\\\Sysmon.exe")
        self.assertEqual(normalized["service_start_type"], "auto start")

    def test_classifies_sca_policy_fixture(self):
        normalized = normalize_wazuh_alert(load_fixture("windows_sca_policy_failed.json"))

        self.assertEqual(normalized["event_kind"], "configuration")
        self.assertEqual(normalized["event_action"], "sca_policy_not_applicable")
        self.assertEqual(
            normalized["sca_policy"],
            "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
        )
        self.assertEqual(normalized["sca_check_id"], "26000")
        self.assertEqual(
            normalized["sca_check_title"],
            "Ensure 'Enforce password history' is set to '24 or more password(s)'.",
        )
        self.assertEqual(normalized["sca_result"], "not applicable")


if __name__ == "__main__":
    unittest.main()
