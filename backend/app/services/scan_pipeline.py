import logging
import tempfile
import uuid
from datetime import datetime, timezone
from typing import BinaryIO, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import IngestionError, SecurityViolationError, ZeroSentinelException
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.analyzers.bandit_analyzer import run_bandit_analysis
from app.services.analyzers.base import FindingDraft
from app.services.analyzers.owasp_mapper import map_cwe_to_owasp_2025
from app.services.analyzers.semgrep_analyzer import run_semgrep_analysis
from app.services.broadcaster import broadcaster
from app.services.function_extractor import extract_functions
from app.services.ingestion.code_ingest import ingest_pasted_code
from app.services.ingestion.git_ingest import clone_git_repository
from app.services.ingestion.zip_ingest import validate_and_extract_zip
from app.services.mitigation_service import get_or_create_mitigation
from app.services.ml_detector import ml_service

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
    4. Sets scan status to 'analyzing_ml'
    5. Extracts functions and runs ML detector inference
    6. Correlates rule findings ('both') and promotes standalone ML findings ('ml')
    7. Persists findings and updates scan status to 'completed'
    8. Broadcasts real-time events over WebSocket
    9. On error, marks scan as 'failed' and guarantees complete directory cleanup
    """
    start_time = datetime.now(timezone.utc)
    current_stage = "ingest"

    async def _run_with_session(session: AsyncSession):
        nonlocal current_stage
        # 1. Update status to 'scanning'
        scan_stmt = select(Scan).where(Scan.scan_id == scan_id)
        result = await session.execute(scan_stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found in database.", scan_id)
            return

        scan.status = "scanning"
        await session.commit()

        # Publish initial ingestion progress
        await broadcaster.publish_progress(
            scan_id=scan.scan_id,
            stage="ingest",
            done=1,
            total=4,
            message="Ingesting and extracting source repository...",
            status="scanning",
        )

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
                current_stage = "rules"
                await broadcaster.publish_progress(
                    scan_id=scan.scan_id,
                    stage="rules",
                    done=2,
                    total=4,
                    message="Executing Bandit and Semgrep static rule checks...",
                    status="scanning",
                )

                findings_drafts: List[FindingDraft] = []

                # Run Bandit
                bandit_findings = run_bandit_analysis(temp_dir)
                findings_drafts.extend(bandit_findings)

                # Run Semgrep
                semgrep_findings = run_semgrep_analysis(temp_dir)
                findings_drafts.extend(semgrep_findings)

                # Deduplicate overlapping static rule findings by file_path, start_line, rule_id
                seen = set()
                deduped_drafts: List[FindingDraft] = []
                for draft in findings_drafts:
                    key = (draft.file_path, draft.start_line, draft.rule_id)
                    if key not in seen:
                        seen.add(key)
                        deduped_drafts.append(draft)

                # 4. ML inference stage
                current_stage = "ml"
                scan.status = "analyzing_ml"
                await session.commit()

                await broadcaster.publish_progress(
                    scan_id=scan.scan_id,
                    stage="ml",
                    done=3,
                    total=4,
                    message="Extracting AST functions and running ML detector...",
                    status="analyzing_ml",
                )

                # Extract functions from ingested files (zero-execution AST parsing)
                extracted_funcs = extract_functions(temp_dir)
                logger.info("Scan %s: extracted %d functions for ML analysis.", scan_id, len(extracted_funcs))

                if extracted_funcs:
                    ml_predictions = ml_service.predict(extracted_funcs)
                    correlated_func_indices = set()

                    # 4a. Corroborate rule findings with ML predictions (source: "both")
                    for rule_finding in deduped_drafts:
                        for idx, fn in enumerate(extracted_funcs):
                            fn_file = fn["file_path"].replace("\\", "/").lstrip("./")
                            finding_file = rule_finding.file_path.replace("\\", "/").lstrip("./")

                            if fn_file == finding_file:
                                fn_start = fn["start_line"]
                                fn_end = fn["end_line"]
                                if fn_start <= rule_finding.start_line <= fn_end:
                                    pred = ml_predictions[idx]
                                    rule_finding.source = "both"
                                    rule_finding.ml_score = pred.get("ml_score")
                                    correlated_func_indices.add(idx)

                    # 4b. Identify standalone ML candidates (source: "ml")
                    for idx, fn in enumerate(extracted_funcs):
                        if idx in correlated_func_indices:
                            continue

                        pred = ml_predictions[idx]
                        score = pred.get("ml_score", 0.0)
                        cwe_guess = pred.get("cwe_guess")

                        if score >= settings.ML_STANDALONE_THRESHOLD and cwe_guess:
                            top_lines = pred.get("top_lines") or [fn["start_line"]]
                            valid_lines = [line for line in top_lines if fn["start_line"] <= line <= fn["end_line"]]
                            if not valid_lines:
                                valid_lines = [fn["start_line"]]

                            f_start = min(valid_lines)
                            f_end = max(valid_lines)

                            fn_lines = fn["code"].splitlines()
                            snippet_offset_start = max(0, f_start - fn["start_line"])
                            snippet_offset_end = min(len(fn_lines), f_end - fn["start_line"] + 1)
                            snippet_text = "\n".join(fn_lines[snippet_offset_start:snippet_offset_end]).strip()
                            if not snippet_text:
                                snippet_text = f"def {fn.get('name', 'function')}..."

                            owasp_cat = map_cwe_to_owasp_2025(cwe_guess)
                            severity = "high" if score >= 0.85 else "medium"
                            risk = round(score * 8.0, 1)

                            ml_finding = FindingDraft(
                                file_path=fn["file_path"],
                                start_line=f_start,
                                end_line=f_end,
                                title=f"Potential unverified vulnerability ({cwe_guess}) flagged by ML detector",
                                severity=severity,
                                risk_score=risk,
                                mitigation=f"Review function '{fn.get('name', 'block')}' for potential {cwe_guess} vulnerability risks.",
                                snippet=snippet_text,
                                cwe_id=cwe_guess,
                                owasp=owasp_cat,
                                source="ml",
                                rule_id=None,
                                ml_score=score,
                            )
                            deduped_drafts.append(ml_finding)

                # 5. Persist findings & mitigations
                current_stage = "aggregation"
                await broadcaster.publish_progress(
                    scan_id=scan.scan_id,
                    stage="aggregation",
                    done=4,
                    total=4,
                    message="Cataloging mitigations and finalizing scan...",
                    status="analyzing_ml",
                )

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

                    # Stream individual finding event over WebSocket
                    finding_event_data = {
                        "id": str(finding.id),
                        "scan_id": str(scan.scan_id),
                        "file_path": finding.file_path,
                        "start_line": finding.start_line,
                        "end_line": finding.end_line,
                        "title": finding.title,
                        "cwe_id": finding.cwe_id,
                        "owasp": finding.owasp,
                        "source": finding.source,
                        "rule_id": finding.rule_id,
                        "snippet": finding.snippet,
                        "ml_score": finding.ml_score,
                        "severity": finding.severity,
                        "risk_score": finding.risk_score,
                        "mitigation": finding.mitigation,
                        "status": finding.status,
                    }
                    await broadcaster.publish_finding(scan.scan_id, finding_event_data)

                # 6. Finalize scan metadata
                scan.findings_count = len(deduped_drafts)
                scan.risk_score = calculate_overall_risk_score(deduped_drafts)
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await session.commit()
                logger.info("Scan %s completed with %d findings.", scan_id, len(deduped_drafts))

                # 7. Publish completion done event
                severity_breakdown = {
                    "critical": sum(1 for d in deduped_drafts if d.severity == "critical"),
                    "high": sum(1 for d in deduped_drafts if d.severity == "high"),
                    "medium": sum(1 for d in deduped_drafts if d.severity == "medium"),
                    "low": sum(1 for d in deduped_drafts if d.severity == "low"),
                }
                duration_seconds = round((scan.completed_at - start_time).total_seconds(), 2)
                await broadcaster.publish_done(
                    scan_id=scan.scan_id,
                    status="completed",
                    risk_score=scan.risk_score,
                    findings_count=scan.findings_count,
                    severity_breakdown=severity_breakdown,
                    duration_seconds=duration_seconds,
                    completed_at=scan.completed_at.isoformat(),
                )

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

            # Determine safe error code and message without exposing secrets or paths
            err_code = "INTERNAL_SCAN_ERROR"
            err_msg = "Scan failed during pipeline processing."
            if isinstance(exc, SecurityViolationError):
                err_code = exc.code
                err_msg = exc.message
            elif isinstance(exc, IngestionError):
                err_code = exc.code
                err_msg = exc.message
            elif "archive" in str(exc).lower() or "zip" in str(exc).lower():
                err_code = "ARCHIVE_LIMIT_EXCEEDED"
                err_msg = "ZIP archive exceeded decompression or entry count boundaries."
            elif "git" in str(exc).lower() or "clone" in str(exc).lower():
                err_code = "GIT_CLONE_FAILED"
                err_msg = "Git repository clone timed out or failed."

            await broadcaster.publish_error(
                scan_id=scan_id,
                code=err_code,
                message=err_msg,
                stage=current_stage,
            )

    if session_override is not None:
        await _run_with_session(session_override)
    else:
        async with AsyncSessionLocal() as session:
            await _run_with_session(session)
