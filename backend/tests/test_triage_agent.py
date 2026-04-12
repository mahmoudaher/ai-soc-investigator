import unittest

from backend.app.agents.triage import triage_agent
from backend.app.models.casefile import CaseFile, Entity, TimelineEvent


def build_casefile() -> CaseFile:
    return CaseFile(
        case_id="CASE-TRIAGE-001",
        raw_alert={
            "title": "Suspicious repeated login failures from unknown IP",
            "ip": "192.168.1.105",
            "user": "service_account",
            "domain": "malicious-site.com",
            "process": "powershell.exe",
        },
        entities=[Entity(type="host", value="workstation-01")],
        timeline=[
            TimelineEvent(
                timestamp=CaseFile.model_fields["created_at"].default_factory(),
                title="Case Created",
                description="Initial case intake.",
                evidence_ids=[],
                agent="system",
                event_type="milestone",
            )
        ],
        summary="Original summary",
    )


class TriageAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_triage_returns_valid_casefile(self):
        state = build_casefile()

        result = await triage_agent(state)

        self.assertIsInstance(result, CaseFile)
        validated = CaseFile.model_validate(result.model_dump())
        self.assertEqual(validated.case_id, state.case_id)

    async def test_triage_updates_expected_fields(self):
        state = build_casefile()

        result = await triage_agent(state)

        self.assertEqual(result.status, "running")
        self.assertEqual(result.category, "credential")
        self.assertEqual(result.severity, "medium")
        self.assertEqual(len(result.timeline), len(state.timeline) + 1)
        self.assertEqual(result.timeline[-1].agent, "triage_agent")
        self.assertEqual(result.timeline[-1].event_type, "analysis")
        self.assertIsNotNone(result.triage)
        self.assertGreater(len(result.triage.plan), 0)
        self.assertEqual(result.agent_runs[-1].agent, "triage_agent")

    async def test_triage_preserves_non_owned_fields(self):
        state = build_casefile()
        original_summary = state.summary
        original_evidence = list(state.evidence)
        original_mitre = list(state.mitre)
        original_recommendations = list(state.recommendations)

        result = await triage_agent(state)

        self.assertEqual(result.summary, original_summary)
        self.assertEqual(result.evidence, original_evidence)
        self.assertEqual(result.mitre, original_mitre)
        self.assertEqual(result.recommendations, original_recommendations)

    async def test_triage_appends_entities_without_overwriting_existing_ones(self):
        state = build_casefile()

        result = await triage_agent(state)

        self.assertEqual(result.entities[0].value, "workstation-01")
        extracted = {(entity.type, entity.value) for entity in result.entities}
        self.assertIn(("ip", "192.168.1.105"), extracted)
        self.assertIn(("user", "service_account"), extracted)
        self.assertIn(("domain", "malicious-site.com"), extracted)
        self.assertIn(("process", "powershell.exe"), extracted)

    async def test_triage_creates_structured_plan_for_recon(self):
        state = build_casefile()

        result = await triage_agent(state)

        self.assertIn("credential", result.triage.summary)
        self.assertGreater(result.triage.confidence, 0.0)
        self.assertTrue(any(step.entity_type == "ip" for step in result.triage.plan))
        self.assertTrue(any("Validate" in step.goal for step in result.triage.plan))


if __name__ == "__main__":
    unittest.main()
