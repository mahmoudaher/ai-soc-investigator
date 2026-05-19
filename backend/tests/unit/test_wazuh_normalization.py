import unittest

from backend.app.normalization.wazuh import normalize_wazuh_alert


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
        self.assertEqual(normalized["user"], "jane")
        self.assertEqual(
            normalized["process"],
            "C:\\Windows\\System32\\svchost.exe",
        )


if __name__ == "__main__":
    unittest.main()
