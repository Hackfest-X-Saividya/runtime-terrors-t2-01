import logging
import tempfile
import uuid
from datetime import datetime, timezone
from typing import BinaryIO, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.analyzers.bandit_analyzer import run_bandit_analysis
from app.services.analyzers.base import FindingDraft
from app.services.analyzers.semgrep_analyzer import run_semgrep_analysis
from app.services.ingestion.code_ingest import ingest_pasted_code
from app.services.ingestion.git_ingest import clone_git_repository
from app.services.ingestion.zip_ingest import validate_and_extract_zip
from app.services.mitigation_service import get_or_create_mitigation

logger = logging.getLogger("zerosentinel.pipeline")


def calculate_overall_risk_score(findings: List[FindingDraft]) -> float:
    """
    Computes a composite normalized risk score (0.0 - 10.0) from findings:
    - 0 findings: 0.0
    - Otherwise: max severity finding base + logarithmic count factor.
    """
    if not findings:
        return 0.0

    max_base = max(f.risk_score for f in findings)
    # Add modest scaling for finding count without exceeding 10.0
    count_factor = min(1.5, 0.2 * (len(findings) - 1))
    composite = round(min(10.0, max_base + count_factor), 1)
    return composite


async def execute_scan_pipeline(
    scan_id: uuid.UUID,
    submission_type: str,
    source_code: Optional[str] = None,
    zip_bytes: Optional[bytes] = None,
    git_url: Optional[str] = None,
    branch: Optional[str] = None,
    language: str = "python",
    session_override: Optional[AsyncSession] = None,
) -> None:
    """
    Asynchronous scanning pipeline orchestrator:
    1. Sets scan status to 'scanning'
    2. Runs ingestion into a temporary directory
    3. Runs static analyzers (Bandit, Semgrep)
    4. Persists findings and updates scan status to 'completed'
    5. On error, marks scan as 'failed' and guarantees complete directory cleanup
    """
    async def _run_with_session(session: AsyncSession):
        # 1. Update status to 'scanning'
        scan_stmt = select(Scan).where(Scan.scan_id == scan_id)
        result = await session.execute(scan_stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found in database.", scan_id)
            return

        scan.status = "scanning"
        await session.commit()

        try:
            # 2. Ingestion inside isolated temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                if submission_type == "code":
                    if not source_code:
                        raise ValueError("source_code required for 'code' submission.")
                    ingest_pasted_code(source_code, temp_dir, language=language)

                elif submission_type == "zip":
                    if not zip_bytes:
                        raise ValueError("zip_bytes required for 'zip' submission.")
                    import io
                    validate_and_extract_zip(io.BytesIO(zip_bytes), temp_dir)

                elif submission_type == "git":
                    if not git_url:
                        raise ValueError("git_url required for 'git' submission.")
                    clone_git_repository(git_url, branch or "main", temp_dir)

                else:
                    raise ValueError(f"Unsupported submission_type: {submission_type}")

                # 3. Execute static analyzers
                findings_drafts: List[FindingDraft] = []

                # Run Bandit
                bandit_findings = run_bandit_analysis(temp_dir)
                findings_drafts.extend(bandit_findings)

                # Run Semgrep
                semgrep_findings = run_semgrep_analysis(temp_dir)
                findings_drafts.extend(semgrep_findings)

                # Deduplicate overlapping findings by file_path and start_line
                seen = set()
                deduped_drafts: List[FindingDraft] = []
                for draft in findings_drafts:
                    key = (draft.file_path, draft.start_line, draft.rule_id)
                    if key not in seen:
                        seen.add(key)
                        deduped_drafts.append(draft)

                # 4. Persist findings & mitigations
                for draft in deduped_drafts:
                    mitigation_id = await get_or_create_mitigation(session, draft)
                    finding = Finding(
                        id=uuid.uuid4(),
                        scan_id=scan.scan_id,
                        mitigation_id=mitigation_id,
                        file_path=draft.file_path,
                        start_line=draft.start_line,
                        end_line=draft.end_line,
                        title=draft.title,
                        cwe_id=draft.cwe_id,
                        owasp=draft.owasp,
                        source=draft.source,
                        rule_id=draft.rule_id,
                        snippet=draft.snippet,
                        ml_score=draft.ml_score,
                        severity=draft.severity,
                        risk_score=draft.risk_score,
                        mitigation=draft.mitigation,
                        status="open",
                    )
                    session.add(finding)

                # 5. Finalize scan metadata
                scan.findings_count = len(deduped_drafts)
                scan.risk_score = calculate_overall_risk_score(deduped_drafts)
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await session.commit()
                logger.info("Scan %s completed with %d findings.", scan_id, len(deduped_drafts))

        except Exception as exc:
            logger.error("Scan %s failed during pipeline execution: %s", scan_id, exc, exc_info=True)
            await session.rollback()
            # Update status to 'failed'
            scan_result = await session.execute(select(Scan).where(Scan.scan_id == scan_id))
            scan_to_fail = scan_result.scalar_one_or_none()
            if scan_to_fail:
                scan_to_fail.status = "failed"
                scan_to_fail.completed_at = datetime.now(timezone.utc)
                await session.commit()

    if session_override is not None:
        await _run_with_session(session_override)
    else:
        async with AsyncSessionLocal() as session:
            await _run_with_session(session)
