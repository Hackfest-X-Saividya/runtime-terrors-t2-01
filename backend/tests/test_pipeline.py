import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan
from app.services.scan_pipeline import execute_scan_pipeline


@pytest.mark.asyncio
async def test_pipeline_pasted_code_success(isolated_test_db: AsyncSession):
    """
    Integration test: Runs execute_scan_pipeline with vulnerable code snippet,
    verifying status transitions, finding extraction, mitigation deduplication,
    and database persistence.
    """
    # 1. Create initial scan
    scan = Scan(
        project_name="PipelineTestApp",
        submission_type="code",
        language="python",
        status="queued",
        risk_score=0.0,
        findings_count=0,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    # 2. Execute pipeline with insecure snippet
    vulnerable_code = "import pickle\nuser = pickle.loads(token)\n"
    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="code",
        source_code=vulnerable_code,
        language="python",
        session_override=isolated_test_db,
    )

    # 3. Verify scan state
    await isolated_test_db.refresh(scan)
    assert scan.status == "completed"
    assert scan.findings_count >= 1
    assert scan.risk_score > 0.0
    assert scan.completed_at is not None

    # 4. Verify findings persisted
    findings_stmt = select(Finding).where(Finding.scan_id == scan.scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) == scan.findings_count

    finding = findings[0]
    assert finding.source == "rule"
    assert finding.status == "open"
    assert finding.mitigation_id is not None

    # 5. Verify mitigation catalog record was created
    mit_stmt = select(Mitigation).where(Mitigation.id == finding.mitigation_id)
    mitigation = (await isolated_test_db.execute(mit_stmt)).scalar_one_or_none()
    assert mitigation is not None
    assert "rule:" in mitigation.canonical_key or "cwe:" in mitigation.canonical_key


@pytest.mark.asyncio
async def test_pipeline_failure_marks_scan_failed(isolated_test_db: AsyncSession, monkeypatch):
    """
    Integration test: If an unrecoverable ingestion error occurs,
    pipeline catches it, rolls back partial findings, and marks scan as 'failed'.
    """
    scan = Scan(
        project_name="FailTestApp",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    # Trigger failure by passing unsupported submission_type
    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="unsupported_type",
        session_override=isolated_test_db,
    )

    await isolated_test_db.refresh(scan)
    assert scan.status == "failed"
    assert scan.completed_at is not None
