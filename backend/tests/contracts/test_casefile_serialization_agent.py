import unittest

from backend.app.agents.recon import recon_agent
from backend.app.agents.evidence import evidence_agent
from backend.app.agents.triage import triage_agent
from backend.app.models.casefile import CaseFile


def build_casefile() -> CaseFile:
    return CaseFile(
        case_id="CASE-SERIAL-001",
        raw_alert={
            "title": "Possible phishing login from suspicious host",
            "ip": "10.10.10.10",
            "user": "employee01",
            "host": "desktop-22",
            "domain": "suspicious-login.example",
        },
    )


class CaseFileSerializationTests(unittest.IsolatedAsyncioTestCase):
    async def test_casefile_round_trip_json_after_agents(self):
        state = build_casefile()

        triaged = await triage_agent(state)
        investigated = await evidence_agent(triaged)
        reconned = await recon_agent(investigated)

        payload = reconned.model_dump_json()
        restored = CaseFile.model_validate_json(payload)

        self.assertEqual(restored.case_id, reconned.case_id)
        self.assertEqual(restored.status, reconned.status)
        self.assertEqual(len(restored.entities), len(reconned.entities))
        self.assertEqual(len(restored.evidence), len(reconned.evidence))
        self.assertEqual(len(restored.timeline), len(reconned.timeline))
        self.assertIsNotNone(restored.triage)

    async def test_serialized_casefile_keeps_required_nested_fields(self):
        state = build_casefile()

        triaged = await triage_agent(state)
        investigated = await evidence_agent(triaged)
        reconned = await recon_agent(investigated)
        restored = CaseFile.model_validate_json(reconned.model_dump_json())

        self.assertTrue(all(entity.id for entity in restored.entities))
        self.assertTrue(all(item.id for item in restored.evidence))
        self.assertTrue(all(event.id for event in restored.timeline))
        self.assertTrue(all(item.source for item in restored.evidence))
        self.assertTrue(all(run.agent for run in restored.agent_runs))
        self.assertTrue(all(step.goal for step in restored.triage.plan))


if __name__ == "__main__":
    unittest.main()
