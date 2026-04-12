import unittest

from backend.app.agents.recon import recon_agent
from backend.app.models.casefile import (
    CaseFile,
    Entity,
    EvidenceItem,
    TriageAssessment,
    TriagePlanStep,
)


def build_casefile() -> CaseFile:
    return CaseFile(
        case_id="CASE-RECON-001",
        raw_alert={"title": "Lab host communicating with internal IP"},
        status="running",
        entities=[
            Entity(type="ip", value="192.168.56.10"),
            Entity(type="host", value="lab-host-01"),
        ],
        evidence=[
            EvidenceItem(
                type="intel",
                payload={"entity_value": "192.168.56.10", "entity_type": "ip", "intel": {"reputation": "unknown"}},
                source="Threat_Intel_API",
                tags=["baseline"],
            )
        ],
        triage=TriageAssessment(
            summary="Internal lab activity needs validation.",
            confidence=0.8,
            plan=[
                TriagePlanStep(
                    entity_type="ip",
                    entity_value="192.168.56.10",
                    goal="Validate whether the IP is internal-only or an external IOC.",
                    rationale="Private addressing can indicate lab traffic instead of an internet threat.",
                    priority="medium",
                ),
                TriagePlanStep(
                    entity_type="host",
                    entity_value="lab-host-01",
                    goal="Validate whether the host belongs to a lab environment.",
                    rationale="Lab hosts often generate expected test activity.",
                    priority="medium",
                ),
            ],
        ),
        summary="Preserve me",
    )


class ReconAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_recon_returns_valid_casefile(self):
        state = build_casefile()

        result = await recon_agent(state)

        self.assertIsInstance(result, CaseFile)
        self.assertEqual(result.agent_runs[-1].agent, "recon_agent")

    async def test_recon_appends_note_evidence_from_triage_plan(self):
        state = build_casefile()

        result = await recon_agent(state)

        new_items = [item for item in result.evidence if item.source == "recon_agent"]
        self.assertEqual(len(new_items), len(state.triage.plan))
        self.assertTrue(any(item.payload["validation"] == "private_ip" for item in new_items))
        self.assertTrue(any(item.payload["validation"] == "lab_host" for item in new_items))

    async def test_recon_preserves_fields_it_does_not_own(self):
        state = build_casefile()

        result = await recon_agent(state)

        self.assertEqual(result.category, state.category)
        self.assertEqual(result.severity, state.severity)
        self.assertEqual(result.entities, state.entities)
        self.assertEqual(result.summary, state.summary)
        self.assertEqual(result.triage, state.triage)

    async def test_recon_repeat_run_is_consistent(self):
        state = build_casefile()

        first_run = await recon_agent(state)
        second_run = await recon_agent(first_run)

        first_recon_count = len([item for item in first_run.evidence if item.source == "recon_agent"])
        second_recon_count = len([item for item in second_run.evidence if item.source == "recon_agent"])
        self.assertEqual(first_recon_count, len(state.triage.plan))
        self.assertEqual(second_recon_count, len(state.triage.plan) * 2)


if __name__ == "__main__":
    unittest.main()
