"""
ZeroSentinel — Reproducible End-to-End Demo Script.

Executes the complete scan lifecycle programmatically on local fixtures:
1. Verifies model artifacts and detector loading.
2. Submits sample Python code (data/samples/vuln_demo.py).
3. Executes zero-execution AST extraction + static rule analysis + ML inference.
4. Correlates findings, displays severity breakdown, CWEs, and risk scores.
5. Simulates triage action (PATCH finding to false_positive).
6. Demonstrates online feedback learning adaptation in the ML detector.
7. Generates HTML and PDF audit reports.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

# Add repo root and backend to python path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))
if str(REPO_ROOT / "ml") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "ml"))

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

from app.models.base import Base
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.scan_pipeline import execute_scan_pipeline
from app.services.ml_detector import ml_service
from app.services.report_service import generate_html_report, generate_pdf_report


async def main():
    print("=" * 72)
    print("  ZeroSentinel: AI-Powered Zero-Day Vulnerability Detection Engine")
    print("  Reproducible Demonstration Walkthrough")
    print("=" * 72)

    # 1. Model Runtime Status
    info = ml_service.get_runtime_info()
    print(f"\n[1] ML INFERENCE STATUS:")
    print(f"    - Model Name:         {info['model_name']}")
    print(f"    - Version:            {info['version']}")
    print(f"    - Engine Status:      {info['status'].upper()}")
    print(f"    - Artifacts Present:  {info['artifacts_present']}")
    print(f"    - Feedback Supported: {info['feedback_supported']}")
    print(f"    - Device:             {info['device']}")

    # 2. Setup In-Memory Isolated Database
    print(f"\n[2] DATABASE INITIALIZATION (Isolated Demo Session):")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    print("    - Ephemeral SQLite database tables initialized successfully.")

    # 3. Read Demo Target Fixture
    sample_file = REPO_ROOT / "data" / "samples" / "vuln_demo.py"
    if not sample_file.exists():
        print(f"    [!] Error: Demo sample not found at {sample_file}")
        return
    code = sample_file.read_text(encoding="utf-8")
    print(f"\n[3] SUBMISSION INGESTION:")
    print(f"    - Fixture:     {sample_file.name} ({len(code)} bytes, {len(code.splitlines())} lines)")
    print(f"    - Source Safe: ZERO submitted code is ever executed or evaluated.")

    scan_id = uuid.uuid4()
    async with session_factory() as session:
        scan = Scan(
            scan_id=scan_id,
            project_name="ZeroSentinelLiveAudit",
            submission_type="code",
            language="python",
            status="queued",
        )
        session.add(scan)
        await session.commit()
        print(f"    - Scan Created: {scan_id} (Status: QUEUED)")

        # 4. Execute Analysis Pipeline
        print(f"\n[4] EXECUTING SCAN PIPELINE...")
        print(f"    - Running AST function extraction...")
        print(f"    - Running Bandit static security analyzers...")
        print(f"    - Running TF-IDF + Logistic Regression ML inference...")
        print(f"    - Correlating findings across rule and ML candidate spaces...")

        await execute_scan_pipeline(
            scan_id=scan_id,
            submission_type="code",
            source_code=code,
            language="python",
            session_override=session,
        )

        await session.refresh(scan)
        print(f"    - Scan Complete: Status = {scan.status.upper()}")
        print(f"    - Total Findings: {scan.findings_count}")
        print(f"    - Overall Risk Score: {scan.risk_score:.1f} / 10.0")

        # 5. Display Findings Table
        stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
        findings = (await session.execute(stmt)).scalars().all()

        print(f"\n[5] DETECTED VULNERABILITY FINDINGS:")
        print(f"    {'SOURCE':<7} {'SEVERITY':<8} {'CWE':<9} {'RISK':<5} {'ML SCORE':<8} {'LINE':<6} {'TITLE'}")
        print("    " + "-" * 75)
        for f in findings:
            ml_sc = f"{f.ml_score:.3f}" if f.ml_score is not None else "N/A"
            print(f"    {f.source.upper():<7} {f.severity.upper():<8} {str(f.cwe_id):<9} {f.risk_score:<5.1f} {ml_sc:<8} {f.start_line:<6} {f.title[:38]}")

        # 6. Triage & Online Feedback Learning Demonstration
        print(f"\n[6] HUMAN-IN-THE-LOOP TRIAGE & FEEDBACK LEARNING:")
        target_finding = next((f for f in findings if f.snippet), None)
        if target_finding:
            print(f"    - Selected Finding for Triage: ID={target_finding.id}")
            print(f"    - Action: User marks finding as 'false_positive'")
            target_finding.status = "false_positive"
            await session.commit()
            print(f"    - Database status updated to: {target_finding.status}")

            # Dispatch feedback
            print(f"    - Dispatched feedback to Contextual Bandit policy...")
            fb_res = ml_service.feedback(
                code=target_finding.snippet,
                status="false_positive",
                func_name=target_finding.title or "finding",
                cwe_id=target_finding.cwe_id,
            )
            print(f"    - Feedback Result: status={fb_res.get('status')}, reward={fb_res.get('reward')}, applied={fb_res.get('applied')}")
            if "score_before" in fb_res and "score_after" in fb_res:
                print(f"    - Score Suppression: {fb_res['score_before']:.3f} -> {fb_res['score_after']:.3f} (delta: {fb_res.get('score_delta'):.4f})")

        # 7. Generate Reports
        print(f"\n[7] GENERATING COMPREHENSIVE REPORTS:")
        out_dir = REPO_ROOT / "temp_demo_reports"
        out_dir.mkdir(exist_ok=True)

        # HTML
        html_content = generate_html_report(scan, findings)
        html_file = out_dir / f"scan_{scan_id}_report.html"
        html_file.write_text(html_content, encoding="utf-8")
        print(f"    - HTML Report saved: {html_file.name} ({len(html_content)} bytes)")

        # PDF
        pdf_bytes = generate_pdf_report(scan, findings)
        pdf_file = out_dir / f"scan_{scan_id}_report.pdf"
        pdf_file.write_bytes(pdf_bytes)
        print(f"    - PDF Report saved:  {pdf_file.name} ({len(pdf_bytes)} bytes)")

    print("\n" + "=" * 72)
    print("  Demonstration Walkthrough Finished Successfully.")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
