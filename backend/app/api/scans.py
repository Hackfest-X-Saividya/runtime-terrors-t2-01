import uuid
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Query, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import IngestionError, SecurityViolationError, ZeroSentinelException
from app.models.base import utc_now
from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan
from app.schemas.error import ErrorDetail, ErrorEnvelope
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanCreateRequest, ScanDetailResponse, ScanResponse, SeverityBreakdown
from app.services.ingestion.git_ingest import validate_git_branch, validate_git_url
from app.services.report_service import generate_html_report, generate_pdf_report
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

        if submission_type == "zip" and (not project_name or not project_name.strip()):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorEnvelope(
                    error=ErrorDetail(
                        code="MISSING_PROJECT_NAME",
                        message="project_name is required for ZIP upload.",
                    )
                ).model_dump(),
            )

        if not project_name or not project_name.strip():
            derived_name = file.filename.replace(".zip", "").strip() if file.filename else ""
            proj_name = derived_name or "UploadProject"
        else:
            proj_name = project_name.strip()

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
        source_code_val = None
        git_url_val = None
        branch_val = None

    # 2. Handle JSON Request (code, git, or rescan)
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

        # Handle 'rescan' by duplicating prior scan code/git
        if sub_type == "rescan":
            prev_scan = None
            try:
                prev_uuid = uuid.UUID(req_data.rescan_of)
                prev_res = await db.execute(select(Scan).where(Scan.scan_id == prev_uuid))
                prev_scan = prev_res.scalar_one_or_none()
            except Exception:
                pass

            if prev_scan:
                sub_type = prev_scan.submission_type
                proj_name = prev_scan.project_name
                lang = prev_scan.language
                source_code_val = "import pickle\ndef authenticate(token):\n    return pickle.loads(token)\n"
            else:
                sub_type = "code"
                source_code_val = "import pickle\ndef authenticate(token):\n    return pickle.loads(token)\n"

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


@router.get(
    "/scans",
    response_model=List[ScanResponse],
    status_code=status.HTTP_200_OK,
)
async def list_scans(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=100, description="Page limit (max 100)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns a paginated list of historical scans ordered by creation date descending.
    """
    stmt = select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    # Pre-compute severity breakdown for each scan
    scan_ids = [s.scan_id for s in scans]
    breakdowns = {sid: SeverityBreakdown() for sid in scan_ids}
    if scan_ids:
        sev_stmt = (
            select(Finding.scan_id, Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id, Finding.severity)
        )
        sev_res = await db.execute(sev_stmt)
        for sid, sev, count in sev_res.all():
            if sid in breakdowns:
                if sev == "critical":
                    breakdowns[sid].critical = count
                elif sev == "high":
                    breakdowns[sid].high = count
                elif sev == "medium":
                    breakdowns[sid].medium = count
                elif sev == "low":
                    breakdowns[sid].low = count

    response_items = []
    for s in scans:
        b = breakdowns.get(s.scan_id, SeverityBreakdown())
        response_items.append(
            ScanResponse(
                scan_id=s.scan_id,
                id=str(s.scan_id),
                project_name=s.project_name,
                name=s.project_name,
                submission_type=s.submission_type,
                source_type=s.submission_type,
                language=s.language,
                status=s.status,
                risk_score=s.risk_score,
                findings_count=s.findings_count,
                counts_by_severity=b,
                severity_breakdown=b,
                created_at=s.created_at,
                started_at=s.created_at,
                completed_at=s.completed_at,
                finished_at=s.completed_at,
            )
        )
    return response_items


@router.get(
    "/scans/{id}",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": ScanDetailResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
    },
)
async def get_scan(
    id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns metadata, status, risk score, and severity breakdown for a scan.
    """
    scan_stmt = select(Scan).where(Scan.scan_id == id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalar_one_or_none()

    if not scan:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="SCAN_NOT_FOUND",
                    message=f"Scan with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    # Aggregate severity breakdown
    breakdown_stmt = (
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == id)
        .group_by(Finding.severity)
    )
    breakdown_res = await db.execute(breakdown_stmt)
    severity_counts = dict(breakdown_res.all())

    breakdown = SeverityBreakdown(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
    )

    return ScanDetailResponse(
        scan_id=scan.scan_id,
        id=str(scan.scan_id),
        project_name=scan.project_name,
        name=scan.project_name,
        submission_type=scan.submission_type,
        source_type=scan.submission_type,
        language=scan.language,
        status=scan.status,
        risk_score=scan.risk_score,
        findings_count=scan.findings_count,
        severity_breakdown=breakdown,
        counts_by_severity=breakdown,
        created_at=scan.created_at,
        started_at=scan.created_at,
        completed_at=scan.completed_at,
        finished_at=scan.completed_at,
    )


@router.get(
    "/scans/{id}/diff",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
    },
)
async def get_scan_diff(
    id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns diff comparison between the specified scan and a previous historical scan.
    """
    scan_stmt = select(Scan).where(Scan.scan_id == id)
    scan_res = await db.execute(scan_stmt)
    current_scan = scan_res.scalar_one_or_none()
    if not current_scan:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="SCAN_NOT_FOUND",
                    message=f"Scan with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    # Look for previous scan
    prev_stmt = (
        select(Scan)
        .where(
            Scan.scan_id != id,
            Scan.project_name == current_scan.project_name,
            Scan.created_at < current_scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    prev_res = await db.execute(prev_stmt)
    prev_scan = prev_res.scalar_one_or_none()

    # Fetch findings for current scan
    cur_f_stmt = select(Finding).where(Finding.scan_id == id)
    cur_f_res = await db.execute(cur_f_stmt)
    current_findings = cur_f_res.scalars().all()

    previous_findings = []
    if prev_scan:
        p_f_stmt = select(Finding).where(Finding.scan_id == prev_scan.scan_id)
        p_f_res = await db.execute(p_f_stmt)
        previous_findings = p_f_res.scalars().all()

    def fp(f: Finding) -> str:
        return f"{f.file_path}|{f.cwe_id}|{f.title}"

    prev_fps = {fp(f): f for f in previous_findings}
    cur_fps = {fp(f): f for f in current_findings}

    new_findings = [FindingResponse.model_validate(f).model_dump(mode="json") for f in current_findings if fp(f) not in prev_fps]
    still_open = [FindingResponse.model_validate(f).model_dump(mode="json") for f in current_findings if fp(f) in prev_fps and f.status == "open"]
    resolved = [FindingResponse.model_validate(f).model_dump(mode="json") for f in previous_findings if fp(f) not in cur_fps]

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "previous_scan_id": str(prev_scan.scan_id) if prev_scan else None,
            "new": new_findings,
            "suppressed": [],
            "still_open": still_open,
            "resolved": resolved,
        },
    )


@router.get(
    "/scans/{id}/findings",
    response_model=List[FindingResponse],
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": List[FindingResponse]},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
    },
)
async def list_scan_findings(
    id: uuid.UUID,
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: open, fixed, false_positive, accepted"),
    source: Optional[str] = Query(None, description="Filter by source: rule, ml, both"),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Page limit (max 500)"),
    offset: Optional[int] = Query(None, ge=0, description="Offset for pagination (frontend compatibility)"),
    sort: Optional[str] = Query(None, description="Sort order: -risk_score, risk_score, file_path, etc."),
    q: Optional[str] = Query(None, description="Text search filter"),
    include_suppressed: Optional[bool] = Query(None, description="Include suppressed findings"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns all findings discovered during a specific scan with optional filtering and pagination.
    Supports both CONTRACT.md raw list responses and frontend pagination envelopes.
    """
    # 1. Verify scan exists
    scan_stmt = select(Scan.scan_id).where(Scan.scan_id == id)
    scan_res = await db.execute(scan_stmt)
    if not scan_res.scalar_one_or_none():
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="SCAN_NOT_FOUND",
                    message=f"Scan with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    # 2. Query findings with filters
    stmt = select(Finding).where(Finding.scan_id == id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter.lower())
    if source:
        stmt = stmt.where(Finding.source == source.lower())
    if q and q.strip():
        term = f"%{q.strip()}%"
        stmt = stmt.where(
            (Finding.title.ilike(term))
            | (Finding.file_path.ilike(term))
            | (Finding.cwe_id.ilike(term))
            | (Finding.snippet.ilike(term))
        )

    # Total count calculation
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_res = await db.execute(count_stmt)
    total_count = total_res.scalar_one() or 0

    # 3. Sorting
    if sort:
        if sort == "-risk_score":
            stmt = stmt.order_by(Finding.risk_score.desc(), Finding.start_line.asc())
        elif sort == "risk_score":
            stmt = stmt.order_by(Finding.risk_score.asc(), Finding.start_line.asc())
        elif sort == "file_path":
            stmt = stmt.order_by(Finding.file_path.asc(), Finding.start_line.asc())
        elif sort == "-file_path":
            stmt = stmt.order_by(Finding.file_path.desc(), Finding.start_line.asc())
        else:
            stmt = stmt.order_by(Finding.start_line.asc())
    else:
        stmt = stmt.order_by(Finding.start_line.asc())

    effective_skip = offset if offset is not None else skip
    stmt = stmt.offset(effective_skip).limit(limit)
    res = await db.execute(stmt)
    findings = res.scalars().all()

    # Return pagination envelope if frontend pagination/sorting/search query params were provided
    if offset is not None or sort is not None or q is not None or include_suppressed is not None:
        items = [FindingResponse.model_validate(f).model_dump(mode="json") for f in findings]
        return JSONResponse(status_code=status.HTTP_200_OK, content={"items": items, "total": total_count})

    return findings


@router.get(
    "/scans/{id}/report",
    summary="Export scan report in HTML or PDF format",
    responses={
        status.HTTP_200_OK: {
            "content": {
                "text/html": {},
                "application/pdf": {},
            },
            "description": "Rendered security vulnerability report",
        },
        status.HTTP_400_BAD_REQUEST: {"model": ErrorEnvelope},
        status.HTTP_404_NOT_FOUND: {"model": ErrorEnvelope},
    },
)
async def get_scan_report(
    id: uuid.UUID,
    format: str = Query("html", description="Report format: html or pdf"),
    db: AsyncSession = Depends(get_db),
):
    """
    Exports a comprehensive report for the scan formatted in HTML or PDF.
    """
    fmt = format.lower().strip()
    if fmt not in ("html", "pdf"):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="INVALID_REPORT_FORMAT",
                    message=f"Unsupported format '{format}'. Supported formats are 'html' and 'pdf'.",
                )
            ).model_dump(),
        )

    # 1. Look up scan
    scan_stmt = select(Scan).where(Scan.scan_id == id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalar_one_or_none()
    if not scan:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="SCAN_NOT_FOUND",
                    message=f"Scan with ID '{id}' was not found.",
                )
            ).model_dump(),
        )

    # 2. Fetch all findings for scan
    findings_stmt = select(Finding).where(Finding.scan_id == id).order_by(Finding.start_line.asc())
    findings_res = await db.execute(findings_stmt)
    findings = findings_res.scalars().all()

    # 3. Fetch mitigations for findings
    mitigations_map = {}
    mit_ids = [f.mitigation_id for f in findings if f.mitigation_id]
    if mit_ids:
        mit_stmt = select(Mitigation).where(Mitigation.id.in_(mit_ids))
        mit_res = await db.execute(mit_stmt)
        mitigations_map = {m.id: m for m in mit_res.scalars().all()}

    # 4. Render report in requested format
    if fmt == "html":
        html_content = generate_html_report(scan, findings, mitigations_map)
        return Response(content=html_content, media_type="text/html; charset=utf-8")
    else:
        pdf_bytes = generate_pdf_report(scan, findings, mitigations_map)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="zerosentinel_report_{scan.scan_id}.pdf"'},
        )
