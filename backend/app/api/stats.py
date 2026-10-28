from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanResponse, SeverityBreakdown
from app.schemas.stats import (
    SeverityDistribution,
    StatsSummaryResponse,
    TopCweItem,
)

router = APIRouter(prefix="/api", tags=["stats"])


@router.get(
    "/stats/summary",
    response_model=StatsSummaryResponse,
    status_code=status.HTTP_200_OK,
)
async def get_stats_summary(
    db: AsyncSession = Depends(get_db),
):
    """
    Returns global vulnerability metrics across all stored scans.
    """
    # 1. Total scans count
    total_scans_res = await db.execute(select(func.count(Scan.scan_id)))
    total_scans = total_scans_res.scalar_one() or 0

    # 2. Total findings count
    total_findings_res = await db.execute(select(func.count(Finding.id)))
    total_findings = total_findings_res.scalar_one() or 0

    # 3. Severity distribution
    sev_stmt = (
        select(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
    )
    sev_res = await db.execute(sev_stmt)
    sev_counts = dict(sev_res.all())

    distribution = SeverityDistribution(
        critical=sev_counts.get("critical", 0),
        high=sev_counts.get("high", 0),
        medium=sev_counts.get("medium", 0),
        low=sev_counts.get("low", 0),
    )

    # 4. Top CWEs (top 5 with non-null cwe_id)
    cwe_stmt = (
        select(Finding.cwe_id, func.count(Finding.id))
        .where(Finding.cwe_id.isnot(None))
        .group_by(Finding.cwe_id)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
    )
    cwe_res = await db.execute(cwe_stmt)
    top_cwes = [
        TopCweItem(cwe_id=cwe, count=count)
        for cwe, count in cwe_res.all()
    ]

    # 5. Average risk score across scans
    avg_stmt = select(func.avg(Scan.risk_score))
    avg_res = await db.execute(avg_stmt)
    avg_score = avg_res.scalar_one()
    average_risk_score = round(float(avg_score), 1) if avg_score is not None else 0.0

    # 6. Source counts (rule, ml, both)
    src_stmt = select(Finding.source, func.count(Finding.id)).group_by(Finding.source)
    src_res = await db.execute(src_stmt)
    src_dict = dict(src_res.all())
    by_source = {
        "rule": src_dict.get("rule", 0),
        "ml": src_dict.get("ml", 0),
        "both": src_dict.get("both", 0),
    }

    # 7. OWASP categories distribution
    owasp_stmt = (
        select(Finding.owasp, func.count(Finding.id))
        .where(Finding.owasp.isnot(None))
        .group_by(Finding.owasp)
    )
    owasp_res = await db.execute(owasp_stmt)
    by_owasp = {ow: count for ow, count in owasp_res.all() if ow}

    # 8. Novel ML findings count
    novel_count = by_source["ml"]

    # 9. Top open findings
    top_f_stmt = (
        select(Finding)
        .where(Finding.status == "open")
        .order_by(Finding.risk_score.desc())
        .limit(10)
    )
    top_f_res = await db.execute(top_f_stmt)
    top_findings = [FindingResponse.model_validate(f) for f in top_f_res.scalars().all()]

    # 10. Last scan
    last_scan_stmt = select(Scan).order_by(Scan.created_at.desc()).limit(1)
    last_scan_res = await db.execute(last_scan_stmt)
    last_scan_model = last_scan_res.scalar_one_or_none()
    last_scan = None
    if last_scan_model:
        # Pre-compute severity breakdown for the last scan
        l_sev_stmt = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == last_scan_model.scan_id)
            .group_by(Finding.severity)
        )
        l_sev_res = await db.execute(l_sev_stmt)
        l_sev_dict = dict(l_sev_res.all())
        l_counts = SeverityBreakdown(
            critical=l_sev_dict.get("critical", 0),
            high=l_sev_dict.get("high", 0),
            medium=l_sev_dict.get("medium", 0),
            low=l_sev_dict.get("low", 0),
        )
        last_scan = ScanResponse(
            scan_id=last_scan_model.scan_id,
            id=str(last_scan_model.scan_id),
            project_name=last_scan_model.project_name,
            name=last_scan_model.project_name,
            submission_type=last_scan_model.submission_type,
            source_type=last_scan_model.submission_type,
            language=last_scan_model.language,
            status=last_scan_model.status,
            risk_score=last_scan_model.risk_score,
            findings_count=last_scan_model.findings_count,
            counts_by_severity=l_counts,
            severity_breakdown=l_counts,
            created_at=last_scan_model.created_at,
            started_at=last_scan_model.created_at,
            completed_at=last_scan_model.completed_at,
            finished_at=last_scan_model.completed_at,
        )

    return StatsSummaryResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        severity_distribution=distribution,
        top_cwes=top_cwes,
        average_risk_score=average_risk_score,
        by_severity=distribution,
        by_source=by_source,
        by_owasp=by_owasp,
        novel_count=novel_count,
        top_findings=top_findings,
        last_scan=last_scan,
    )
