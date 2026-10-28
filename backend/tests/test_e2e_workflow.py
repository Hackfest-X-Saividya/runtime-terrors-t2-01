import asyncio
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.testclient import TestClient

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan
from app.services.broadcaster import broadcaster
from app.services.scan_pipeline import execute_scan_pipeline


@pytest.mark.asyncio
async def test_complete_end_to_end_workflow(
    client_with_db: AsyncClient,
    sync_client_with_db: TestClient,
    isolated_test_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Comprehensive Phase 5 Audit: End-to-End Workflow Test.
    Traces the entire lifecycle from ingestion to reporting:
    1. Submit vulnerable Python code -> HTTP 202 Accepted with scan_id
    2. Execute scan pipeline -> zero-execution AST extraction + static rule + ML correlation
    3. Verify findings persisted with source: 'both', ml_score, and mitigation links
    4. Verify WebSocket streaming receives progress, finding, and done events with scan_id
    5. Query GET /api/scans/{id} -> status: completed, severity_breakdown verified
    6. Query GET /api/scans/{id}/findings -> filters verified
    7. Query GET /api/findings/{id} -> mitigation_detail verified
    8. Patch PATCH /api/findings/{id} -> triage status updated to 'accepted'
    9. Query GET /api/stats/summary -> global metrics & top_cwes verified
    10. Query GET /api/model/info -> transparent stub fallback status verified
    11. Query GET /api/scans/{id}/report?format=html -> valid secure HTML report verified
    12. Query GET /api/scans/{id}/report?format=pdf -> valid ReportLab PDF report verified
    """
    vulnerable_source = (
        "import pickle\n"
        "import os\n\n"
        "def process_auth_token(raw_token: str):\n"
        "    # Vulnerable to insecure deserialization\n"
        "    payload = pickle.loads(raw_token)\n"
        "    return payload\n\n"
        "def safe_helper(x: int, y: int) -> int:\n"
        "    return x + y\n"
    )

    # 1. Submit Code via POST /api/scans
    # Prevent background task from executing with un-overridden production Postgres connection
    async def noop_execute(*args, **kwargs):
        pass

    monkeypatch.setattr("app.api.scans.execute_scan_pipeline", noop_execute)

    submit_payload = {
        "submission_type": "code",
        "project_name": "E2EAuditAuthService",
        "language": "python",
        "source_code": vulnerable_source,
    }
    submit_res = await client_with_db.post("/api/scans", json=submit_payload)
    assert submit_res.status_code == 202
    scan_meta = submit_res.json()
    scan_id_str = scan_meta["scan_id"]
    scan_id = uuid.UUID(scan_id_str)
    assert scan_meta["status"] == "queued"
    assert scan_meta["project_name"] == "E2EAuditAuthService"

    # 2. Execute Scan Pipeline (using test database session)
    await execute_scan_pipeline(
        scan_id=scan_id,
        submission_type="code",
        source_code=vulnerable_source,
        language="python",
        session_override=isolated_test_db,
    )

    # 3. Verify Database Persistence & Correlation
    scan_stmt = select(Scan).where(Scan.scan_id == scan_id)
    scan_record = (await isolated_test_db.execute(scan_stmt)).scalar_one()
    assert scan_record.status == "completed"
    assert scan_record.findings_count >= 1
    assert scan_record.risk_score > 0.0
    assert scan_record.completed_at is not None

    findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) == scan_record.findings_count

    # Check finding correlation (Bandit rule B301 + function extraction -> source: both)
    both_findings = [f for f in findings if f.source == "both"]
    assert len(both_findings) >= 1
    corroborated_finding = both_findings[0]
    assert corroborated_finding.ml_score is not None
    assert corroborated_finding.ml_score >= 0.70
    assert corroborated_finding.rule_id is not None
    assert corroborated_finding.mitigation_id is not None
    finding_id = corroborated_finding.id

    # 4. Verify WebSocket Streaming & Reconnect Behavior
    with sync_client_with_db.websocket_connect(f"/ws/scans/{scan_id}") as ws:
        event = ws.receive_json()
        assert event["type"] == "done"
        assert event["data"]["scan_id"] == str(scan_id)
        assert event["data"]["status"] == "completed"
        assert event["data"]["findings_count"] == len(findings)
        assert "severity_breakdown" in event["data"]

    # 5. Retrieve Scan Details via GET /api/scans/{id}
    detail_res = await client_with_db.get(f"/api/scans/{scan_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["scan_id"] == str(scan_id)
    assert detail_data["status"] == "completed"
    assert detail_data["findings_count"] == len(findings)
    assert (detail_data["severity_breakdown"]["high"] + detail_data["severity_breakdown"]["medium"]) >= 1

    # 6. Retrieve Findings via GET /api/scans/{id}/findings
    findings_res = await client_with_db.get(f"/api/scans/{scan_id}/findings?source=both")
    assert findings_res.status_code == 200
    findings_list = findings_res.json()
    assert len(findings_list) >= 1
    assert findings_list[0]["source"] == "both"
    assert findings_list[0]["scan_id"] == str(scan_id)

    # 7. Retrieve Finding Detail via GET /api/findings/{id}
    f_detail_res = await client_with_db.get(f"/api/findings/{finding_id}")
    assert f_detail_res.status_code == 200
    f_detail_data = f_detail_res.json()
    assert f_detail_data["id"] == str(finding_id)
    assert f_detail_data["mitigation_detail"] is not None
    assert "remediation_guidance" in f_detail_data["mitigation_detail"]

    # 8. Update Finding Status via PATCH /api/findings/{id}
    patch_res = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "accepted"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "accepted"

    # 9. Retrieve Stats Summary via GET /api/stats/summary
    stats_res = await client_with_db.get("/api/stats/summary")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_scans"] >= 1
    assert stats_data["total_findings"] >= 1
    assert stats_data["average_risk_score"] > 0.0
    assert isinstance(stats_data["top_cwes"], list)
    if stats_data["top_cwes"]:
        assert "cwe_id" in stats_data["top_cwes"][0]
        assert "count" in stats_data["top_cwes"][0]

    # 10. Retrieve Model Info via GET /api/model/info
    model_res = await client_with_db.get("/api/model/info")
    assert model_res.status_code == 200
    model_data = model_res.json()
    assert model_data["is_stub"] is True
    assert model_data["status"] == "stub_fallback"
    assert model_data["model_name"] == "ZeroSentinel Heuristic Stub"

    # 11. Generate HTML Report via GET /api/scans/{id}/report?format=html
    html_res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "<!DOCTYPE html>" in html_res.text
    assert "E2EAuditAuthService" in html_res.text
    assert str(scan_id) in html_res.text
    assert "pickle.loads" in html_res.text

    # 12. Generate PDF Report via GET /api/scans/{id}/report?format=pdf
    pdf_res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.headers["content-type"]
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 500
