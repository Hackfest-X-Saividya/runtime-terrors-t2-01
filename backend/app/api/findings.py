import logging
import uuid
from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.schemas.error import ErrorDetail, ErrorEnvelope
from app.schemas.finding import (
    FindingDetailResponse,
    FindingResponse,
    FindingUpdateRequest,
    MitigationDetail,
)
from app.services.ml_detector import ml_service

logger = logging.getLogger("zerosentinel.findings")


def _safe_dispatch_feedback(code: str, status: str, func_name: str) -> None:
    """Safe background worker protecting against any unhandled detector/IO exceptions."""
    try:
        ml_service.feedback(code=code, status=status, func_name=func_name)
    except Exception as exc:
        logger.warning("[FEEDBACK_BACKGROUND] Feedback dispatch failed gracefully: %s", exc)


router = APIRouter(prefix="/api", tags=["findings"])


@router.get(
    "/findings/{id}",
    response_model=FindingDetailResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": FindingDetailResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
    },
)
async def get_finding(
    id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns details for a single finding, including optional extended catalog mitigation references.
    """
    finding_stmt = select(Finding).where(Finding.id == id)
    result = await db.execute(finding_stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="FINDING_NOT_FOUND",
                    message=f"Finding with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    mitigation_detail = None
    if finding.mitigation_id:
        mit_stmt = select(Mitigation).where(Mitigation.id == finding.mitigation_id)
        mit_res = await db.execute(mit_stmt)
        mit = mit_res.scalar_one_or_none()
        if mit:
            mitigation_detail = MitigationDetail(
                id=mit.id,
                title=mit.title,
                remediation_guidance=mit.remediation_guidance,
                code_diff=mit.code_diff,
                references_json=mit.references_json,
            )

    return FindingDetailResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        file_path=finding.file_path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        title=finding.title,
        cwe_id=finding.cwe_id,
        owasp=finding.owasp,
        source=finding.source,
        rule_id=finding.rule_id,
        snippet=finding.snippet,
        ml_score=finding.ml_score,
        severity=finding.severity,
        risk_score=finding.risk_score,
        mitigation=finding.mitigation,
        status=finding.status,
        mitigation_detail=mitigation_detail,
    )


@router.patch(
    "/findings/{id}",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": FindingResponse},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorEnvelope},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"model": ErrorEnvelope},
    },
)
async def update_finding(
    id: uuid.UUID,
    payload: FindingUpdateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Updates finding triage status (open, fixed, false_positive, accepted).
    Optionally enqueues safe online feedback learning in background tasks.
    """
    finding_stmt = select(Finding).where(Finding.id == id)
    result = await db.execute(finding_stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="FINDING_NOT_FOUND",
                    message=f"Finding with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    previous_status = finding.status
    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)

    # Safe asynchronous feedback learning dispatch
    # Only dispatched if status actually transitioned, avoiding duplicate feedback runs
    if finding.status != previous_status and finding.snippet and finding.snippet.strip():
        background_tasks.add_task(
            _safe_dispatch_feedback,
            code=finding.snippet,
            status=payload.status,
            func_name=finding.title or "finding",
        )

    return finding
