from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
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

    return StatsSummaryResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        severity_distribution=distribution,
        top_cwes=top_cwes,
        average_risk_score=average_risk_score,
    )
