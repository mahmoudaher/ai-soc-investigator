import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.casefile import CaseCheckpoint, CaseFile, utc_now


async def fake_db():
    yield object()


class WazuhIngestionApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[get_db] = fake_db

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_ingests_wazuh_alert_without_running_workflow(self):
        raw_alert = {
            "timestamp": "2026-05-16T10:15:30.123+0000",
            "rule": {
                "level": 7,
                "description": "sshd: authentication failed.",
                "id": "5716",
                "groups": ["syslog", "sshd", "authentication_failed"],
            },
            "agent": {"id": "002", "name": "ubuntu-victim"},
            "id": "1778936130.123456",
            "data": {"srcip": "10.0.2.15", "srcuser": "admin"},
        }

        with patch(
            "backend.app.main.upsert_case",
            new_callable=AsyncMock,
        ) as upsert, patch(
            "backend.app.main.create_case_checkpoint",
            new_callable=AsyncMock,
        ) as create_checkpoint:
            client = TestClient(app)
            response = client.post(
                "/alerts/wazuh?run_workflow=false",
                json=raw_alert,
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "new")
        self.assertEqual(payload["case_file"]["raw_alert"]["source"], "wazuh")
        self.assertEqual(payload["case_file"]["raw_alert"]["ip"], "10.0.2.15")
        self.assertEqual(payload["case_file"]["raw_alert"]["user"], "admin")
        self.assertEqual(upsert.await_count, 1)
        self.assertEqual(create_checkpoint.await_count, 1)
        self.assertEqual(create_checkpoint.await_args.args[2], "ingest")

    def test_ingests_wazuh_alert_and_checkpoints_each_workflow_node(self):
        raw_alert = {
            "timestamp": "2026-05-16T10:15:30.123+0000",
            "rule": {
                "level": 7,
                "description": "sshd: authentication failed.",
                "id": "5716",
                "groups": ["syslog", "sshd", "authentication_failed"],
            },
            "agent": {"id": "002", "name": "ubuntu-victim"},
            "id": "1778936130.123456",
            "data": {"srcip": "10.0.2.15", "srcuser": "admin"},
        }

        with patch(
            "backend.app.main.upsert_case",
            new_callable=AsyncMock,
        ) as initial_upsert, patch(
            "backend.app.main.create_case_checkpoint",
            new_callable=AsyncMock,
        ) as initial_checkpoint, patch(
            "backend.app.orchestration.checkpointing.upsert_case",
            new_callable=AsyncMock,
        ) as checkpoint_upsert, patch(
            "backend.app.orchestration.checkpointing.create_case_checkpoint",
            new_callable=AsyncMock,
        ) as workflow_checkpoint:
            client = TestClient(app)
            response = client.post(
                "/alerts/wazuh?run_workflow=true",
                json=raw_alert,
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["severity"], "medium")
        self.assertEqual(payload["category"], "credential")
        self.assertEqual(initial_upsert.await_count, 1)
        self.assertEqual(initial_checkpoint.await_count, 1)
        self.assertEqual(initial_checkpoint.await_args.args[2], "ingest")
        self.assertEqual(checkpoint_upsert.await_count, 4)
        self.assertEqual(workflow_checkpoint.await_count, 4)

        checkpoint_statuses = [
            call.args[1].status
            for call in checkpoint_upsert.await_args_list
        ]
        self.assertEqual(
            checkpoint_statuses,
            ["running", "running", "running", "completed"],
        )
        checkpoint_names = [
            call.args[2]
            for call in workflow_checkpoint.await_args_list
        ]
        self.assertEqual(
            checkpoint_names,
            ["triage", "recon", "evidence", "finalizer"],
        )

    def test_reads_case_checkpoints(self):
        case_file = CaseFile(
            case_id="CASE-CHECKPOINT-001",
            raw_alert={"title": "sshd: authentication failed.", "source": "wazuh"},
        )
        checkpoint = CaseCheckpoint(
            id=1,
            case_id=case_file.case_id,
            node_name="ingest",
            status="new",
            severity=None,
            category=None,
            case_file=case_file,
            created_at=utc_now(),
        )

        with patch(
            "backend.app.main.get_case",
            new_callable=AsyncMock,
            return_value=case_file,
        ), patch(
            "backend.app.main.list_case_checkpoints",
            new_callable=AsyncMock,
            return_value=[checkpoint],
        ):
            client = TestClient(app)
            response = client.get(f"/cases/{case_file.case_id}/checkpoints")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["node_name"], "ingest")
        self.assertEqual(payload[0]["case_id"], case_file.case_id)


if __name__ == "__main__":
    unittest.main()
