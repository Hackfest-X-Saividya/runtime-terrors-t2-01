import uuid
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import IngestionError, SecurityViolationError, ZeroSentinelException
from app.models.base import utc_now
from app.models.scan import Scan
from app.schemas.error import ErrorDetail, ErrorEnvelope
from app.schemas.scan import ScanCreateRequest, ScanResponse
from app.services.ingestion.git_ingest import validate_git_branch, validate_git_url
from app.services.scan_pipeline import execute_scan_pipeline

router = APIRouter(prefix="/api", tags=["scans"])


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        status.HTTP_202_ACCEPTED: {"model": ScanResponse},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorEnvelope},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"model": ErrorEnvelope},
    },
)
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    # Multipart form fields for ZIP upload (optional if JSON body is sent)
    submission_type: Optional[str] = Form(None),
    project_name: Optional[str] = Form(None),
    language: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Submits source code for analysis via:
    - Pasted code (JSON)
    - ZIP archive (multipart/form-data)
    - Git repository URL (JSON)
    Responds asynchronously with 202 Accepted.
    """
    content_type = request.headers.get("content-type", "")

    # 1. Handle Multipart / Form Upload (ZIP submission)
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        if not project_name or not project_name.strip():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="MISSING_PROJECT_NAME",
                        message="project_name is required for ZIP upload.",
                    )
                ).model_dump(),
            )
        if not file or not getattr(file, "filename", None):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="MISSING_FILE",
                        message="A ZIP file must be uploaded under the 'file' field.",
                    )
                ).model_dump(),
            )

        # Read zip bytes into memory and verify size ceiling
        zip_bytes = await file.read()
        if len(zip_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="ARCHIVE_LIMIT_EXCEEDED",
                        message=f"ZIP archive exceeds limit of {settings.MAX_UPLOAD_SIZE_BYTES} bytes.",
                    )
                ).model_dump(),
            )

        sub_type = "zip"
        lang = (language or "python").strip()
        proj_name = project_name.strip()
        source_code_val = None
        git_url_val = None
        branch_val = None

    # 2. Handle JSON Request (code or git)
    else:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="INVALID_JSON",
                        message="Request body must be valid JSON.",
                    )
                ).model_dump(),
            )

        try:
            req_data = ScanCreateRequest(**body)
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="INVALID_PAYLOAD",
                        message=str(exc),
                    )
                ).model_dump(),
            )

        sub_type = req_data.submission_type
        proj_name = req_data.project_name
        lang = req_data.language
        source_code_val = req_data.source_code
        git_url_val = req_data.git_url
        branch_val = req_data.branch
        zip_bytes = None

        # Pre-validate Git parameters synchronously so invalid requests reject fast
        if sub_type == "git":
            try:
                validate_git_url(git_url_val)
                branch_val = validate_git_branch(branch_val)
            except ZeroSentinelException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content=ErrorEnvelope(
                        error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details)
                    ).model_dump(),
                )

    # 3. Create initial Scan record in database
    new_scan = Scan(
        scan_id=uuid.uuid4(),
        project_name=proj_name,
        submission_type=sub_type,
        language=lang,
        status="queued",
        risk_score=0.0,
        findings_count=0,
        created_at=utc_now(),
        completed_at=None,
    )

    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # 4. Enqueue background execution task
    background_tasks.add_task(
        execute_scan_pipeline,
        scan_id=new_scan.scan_id,
        submission_type=sub_type,
        source_code=source_code_val,
        zip_bytes=zip_bytes,
        git_url=git_url_val,
        branch=branch_val,
        language=lang,
    )

    return new_scan
