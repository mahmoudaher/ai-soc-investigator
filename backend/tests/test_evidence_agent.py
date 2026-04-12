import unittest

from backend.app.agents.evidence import evidence_agent
from backend.app.models.casefile import CaseFile, Entity, EvidenceItem, TimelineEvent


def build_casefile() -> CaseFile:
    return CaseFile(
        case_id="CASE-EVIDENCE-001",
        raw_alert={"title": "Phishing domain contacted"},
        status="running",
        entities=[
            Entity(type="ip", value="8.8.8.8"),
            Entity(type="domain", value="example-bad-site.com"),
        ],
        evidence=[
            EvidenceItem(
                type="note",
                payload={"note": "Existing analyst note"},
                source="analyst",
                tags=["baseline"],
            )
        ],
        timeline=[
            TimelineEvent(
                timestamp=CaseFile.model_fields["created_at"].default_factory(),
                title="Pre-Triage Completed",
                description="Initial triage completed based on heuristic rules.",
                evidence_ids=[],
                agent="triage_agent",
                event_type="analysis",
            )
        ],
        summary="Keep me unchanged",
    )


class EvidenceAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_evidence_returns_valid_casefile(self):
        state = build_casefile()

        result = await evidence_agent(state)

        self.assertIsInstance(result, CaseFile)
        validated = CaseFile.model_validate(result.model_dump())
        self.assertEqual(validated.case_id, state.case_id)

    async def test_evidence_writes_to_real_evidence_field(self):
        state = build_casefile()

        result = await evidence_agent(state)

        self.assertFalse(hasattr(result, "evidences"))
        self.assertEqual(len(result.evidence), len(state.evidence) + len(state.entities))
        for item in result.evidence[1:]:
            self.assertEqual(item.type, "intel")
            self.assertIn("entity_value", item.payload)
            self.assertIn("entity_type", item.payload)
            self.assertIn("intel", item.payload)

    async def test_evidence_uses_allowed_status_and_event_type(self):
        state = build_casefile()

        result = await evidence_agent(state)

        self.assertIn(result.status, {"new", "running", "completed", "failed", "escalated"})
        self.assertEqual(result.timeline[-1].event_type, "analysis")
        self.assertEqual(result.timeline[-1].agent, "evidence_agent")
        self.assertEqual(result.agent_runs[-1].agent, "evidence_agent")

    async def test_evidence_preserves_non_owned_fields(self):
        state = build_casefile()
        original_category = state.category
        original_severity = state.severity
        original_entities = list(state.entities)
        original_summary = state.summary
        original_triage = state.triage

        result = await evidence_agent(state)

        self.assertEqual(result.category, original_category)
        self.assertEqual(result.severity, original_severity)
        self.assertEqual(result.entities, original_entities)
        self.assertEqual(result.summary, original_summary)
        self.assertEqual(result.triage, original_triage)

    async def test_evidence_repeat_run_appends_more_evidence_consistently(self):
        state = build_casefile()

        first_run = await evidence_agent(state)
        second_run = await evidence_agent(first_run)

        self.assertEqual(len(first_run.evidence), len(state.evidence) + len(state.entities))
        self.assertEqual(len(second_run.evidence), len(first_run.evidence) + len(first_run.entities))
        self.assertEqual(second_run.timeline[-1].agent, "evidence_agent")


if __name__ == "__main__":
    unittest.main()
