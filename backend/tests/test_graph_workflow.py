import unittest

from backend.app.models.casefile import CaseFile
from backend.app.orchestration.graph import build_case_workflow


class GraphWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_graph_runs_end_to_end_and_returns_casefile(self):
        app = build_case_workflow()
        initial_state = CaseFile(
            case_id="CASE-GRAPH-001",
            raw_alert={
                "title": "Suspicious repeated login failures from lab host",
                "ip": "192.168.1.105",
                "user": "service_account",
                "host": "lab-host-01",
                "domain": "malicious-site.com",
                "source": "wazuh",
            },
        )

        final_state = await app.ainvoke(initial_state)
        case_file = final_state if isinstance(final_state, CaseFile) else CaseFile.model_validate(final_state)

        self.assertIsInstance(case_file, CaseFile)
        self.assertEqual(case_file.status, "running")
        self.assertGreaterEqual(len(case_file.entities), 4)
        self.assertEqual(len(case_file.timeline), 3)
        self.assertGreater(len(case_file.evidence), len(case_file.entities))
        self.assertIsNotNone(case_file.triage)
        self.assertEqual(len(case_file.agent_runs), 3)
        self.assertEqual(case_file.timeline[0].agent, "triage_agent")
        self.assertEqual(case_file.timeline[1].agent, "evidence_agent")
        self.assertEqual(case_file.timeline[2].agent, "recon_agent")
        self.assertTrue(any(item.payload.get("validation") == "private_ip" for item in case_file.evidence if item.source == "recon_agent"))
        self.assertTrue(any(item.payload.get("validation") == "lab_host" for item in case_file.evidence if item.source == "recon_agent"))


if __name__ == "__main__":
    unittest.main()
