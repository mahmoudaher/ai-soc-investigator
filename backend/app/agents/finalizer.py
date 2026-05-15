from backend.app.models.casefile import CaseFile, utc_now


async def finalizer_node(state: CaseFile) -> CaseFile:
    if state.status in {"completed", "failed", "escalated"}:
        return state.model_copy(update={"updated_at": utc_now()})

    has_error = any(run.status == "error" for run in state.agent_runs)
    final_status = "failed" if has_error else "completed"

    return state.model_copy(
        update={
            "status": final_status,
            "updated_at": utc_now(),
        }
    )