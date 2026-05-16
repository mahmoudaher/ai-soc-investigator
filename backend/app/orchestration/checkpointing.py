from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.repository import create_case_checkpoint, upsert_case
from backend.app.models.casefile import CaseFile
from backend.app.orchestration.graph import build_case_workflow


async def run_case_workflow_with_checkpoints(
    session: AsyncSession,
    case_file: CaseFile,
) -> CaseFile:
    workflow = build_case_workflow()
    latest_case_file = case_file

    async for chunk in workflow.astream(case_file):
        if not chunk:
            continue

        node_name, node_state = next(iter(chunk.items()))
        latest_case_file = (
            node_state
            if isinstance(node_state, CaseFile)
            else CaseFile.model_validate(node_state)
        )
        await upsert_case(session, latest_case_file)
        await create_case_checkpoint(session, latest_case_file, node_name)

    return latest_case_file
