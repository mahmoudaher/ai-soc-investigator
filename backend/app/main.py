import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.repository import (
    create_case_checkpoint,
    get_case,
    list_case_checkpoints,
    list_cases,
    upsert_case,
)
from backend.app.db.session import get_db, init_db, AsyncSessionLocal
from backend.app.models.casefile import CaseCheckpoint, CaseFile
from backend.app.normalization.wazuh import normalize_wazuh_alert
from backend.app.orchestration.checkpointing import run_case_workflow_with_checkpoints

class IngestAlertResponse(BaseModel):
    case_id: str
    status: str
    severity: str | None = None
    category: str | None = None
    case_file: CaseFile

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("AUTO_CREATE_TABLES", "").lower() in {"1", "true", "yes"}:
        await init_db()
    yield

app = FastAPI(
    title="AI SOC Investigator API",
    version="0.1.0",
    lifespan=lifespan,
)

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

# دالة مساعدة لتشغيل البايبلاين في الخلفية مع سيشن مستقلة للداتا بيز
async def background_workflow_runner(case_id: str):
    async with AsyncSessionLocal() as session:
        case_file = await get_case(session, case_id)
        if case_file:
            try:
                await run_case_workflow_with_checkpoints(session, case_file)
            except Exception as e:
                print(f"[-] Background workflow failed for case {case_id}: {e}")

@app.post("/alerts/wazuh", response_model=IngestAlertResponse)
async def ingest_wazuh_alert(
    alert: dict[str, Any],
    background_tasks: BackgroundTasks,
    run_workflow: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
) -> IngestAlertResponse:
    normalized_alert = normalize_wazuh_alert(alert)
    case_file = CaseFile(
        raw_alert=normalized_alert,
        source=normalized_alert.get("source"),
    )

    try:
        await upsert_case(db, case_file)
        await create_case_checkpoint(db, case_file, "ingest")
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database persistence failed: {error.__class__.__name__}",
        ) from error

    # إرسال العمل الثقيل للخلفية بدلاً من تعطيل استجابة السيرفر
    if run_workflow:
        background_tasks.add_task(background_workflow_runner, case_file.case_id)

    return IngestAlertResponse(
        case_id=case_file.case_id,
        status=case_file.status,
        severity=case_file.severity,
        category=case_file.category,
        case_file=case_file,
    )

@app.get("/cases", response_model=list[CaseFile])
async def read_cases(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[CaseFile]:
    try:
        return await list_cases(db, limit=limit)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database read failed: {error.__class__.__name__}",
        ) from error

@app.get("/cases/{case_id}", response_model=CaseFile)
async def read_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> CaseFile:
    try:
        case_file = await get_case(db, case_id)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database read failed: {error.__class__.__name__}",
        ) from error
    if case_file is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_file

@app.get("/cases/{case_id}/checkpoints", response_model=list[CaseCheckpoint])
async def read_case_checkpoints(
    case_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> list[CaseCheckpoint]:
    try:
        case_file = await get_case(db, case_id)
        if case_file is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return await list_case_checkpoints(db, case_id=case_id, limit=limit)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database read failed: {error.__class__.__name__}",
        ) from error