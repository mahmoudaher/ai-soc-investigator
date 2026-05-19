from typing import Optional

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.models import CaseCheckpointRecord, CaseRecord
from backend.app.models.casefile import CaseCheckpoint, CaseFile, utc_now


def _case_to_record_values(case_file: CaseFile) -> dict:
    return {
        "status": case_file.status,
        "severity": case_file.severity,
        "category": case_file.category,
        "priority": case_file.priority,
        "source": case_file.source,
        "raw_alert": case_file.raw_alert,
        "case_file": case_file.model_dump(mode="json"),
        "created_at": case_file.created_at,
        "updated_at": case_file.updated_at,
    }


async def upsert_case(session: AsyncSession, case_file: CaseFile) -> CaseRecord:
    record = await session.get(CaseRecord, case_file.case_id)
    values = _case_to_record_values(case_file)

    if record is None:
        record = CaseRecord(case_id=case_file.case_id, **values)
        session.add(record)
    else:
        for field, value in values.items():
            setattr(record, field, value)

    await session.commit()
    await session.refresh(record)
    return record


async def get_case(session: AsyncSession, case_id: str) -> Optional[CaseFile]:
    record = await session.get(CaseRecord, case_id)
    if record is None:
        return None
    return CaseFile.model_validate(record.case_file)


async def list_cases(session: AsyncSession, limit: int = 50) -> list[CaseFile]:
    statement: Select[tuple[CaseRecord]] = (
        select(CaseRecord)
        .order_by(CaseRecord.updated_at.desc())
        .limit(limit)
    )
    result = await session.execute(statement)
    return [
        CaseFile.model_validate(record.case_file)
        for record in result.scalars().all()
    ]


def _checkpoint_to_model(record: CaseCheckpointRecord) -> CaseCheckpoint:
    return CaseCheckpoint(
        id=record.id,
        case_id=record.case_id,
        node_name=record.node_name,
        status=record.status,
        severity=record.severity,
        category=record.category,
        case_file=CaseFile.model_validate(record.case_file),
        created_at=record.created_at,
    )


async def create_case_checkpoint(
    session: AsyncSession,
    case_file: CaseFile,
    node_name: str,
) -> CaseCheckpointRecord:
    record = CaseCheckpointRecord(
        case_id=case_file.case_id,
        node_name=node_name,
        status=case_file.status,
        severity=case_file.severity,
        category=case_file.category,
        case_file=case_file.model_dump(mode="json"),
        created_at=utc_now(),
    )
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


async def list_case_checkpoints(
    session: AsyncSession,
    case_id: str,
    limit: int = 100,
) -> list[CaseCheckpoint]:
    statement: Select[tuple[CaseCheckpointRecord]] = (
        select(CaseCheckpointRecord)
        .where(CaseCheckpointRecord.case_id == case_id)
        .order_by(CaseCheckpointRecord.id.asc())
        .limit(limit)
    )
    result = await session.execute(statement)
    return [
        _checkpoint_to_model(record)
        for record in result.scalars().all()
    ]
