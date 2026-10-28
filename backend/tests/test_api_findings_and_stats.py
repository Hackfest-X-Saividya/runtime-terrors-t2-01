import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_list_scans_pagination(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    # Insert 3 test scans
    for i in range(3):
        scan = Scan(
            scan_id=uuid.uuid4(),
            project_name=f"Project_{i}",
            submission_type="code",
            language="python",
            status="completed",
            risk_score=float(i * 2),
            findings_count=i,
        )
        isolated_test_db.add(scan)
    await isolated_test_db.commit()

    # Query with limit 2
    res = await client_with_db.get("/api/scans?skip=0&limit=2")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert "scan_id" in data[0]
    assert "project_name" in data[0]

    # Query with skip 2
    res2 = await client_with_db.get("/api/scans?skip=2&limit=2")
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2) >= 1


@pytest.mark.asyncio
async def test_get_scan_detail_and_404(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="DetailTestProject",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=7.5,
        findings_count=2,
    )
    isolated_test_db.add(scan)

    # Add findings with specific severities
    f1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="Test High",
        severity="high",
        risk_score=7.5,
        mitigation="Fix it",
        snippet="code snippet",
        status="open",
        source="rule",
    )
    f2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="main.py",
        start_line=5,
        end_line=6,
        title="Test Medium",
        severity="medium",
        risk_score=5.0,
        mitigation="Fix it too",
        snippet="code snippet 2",
        status="open",
        source="ml",
    )
    isolated_test_db.add_all([f1, f2])
    await isolated_test_db.commit()

    # Test existing scan
    res = await client_with_db.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == str(scan_id)
    assert data["severity_breakdown"]["high"] == 1
    assert data["severity_breakdown"]["medium"] == 1
    assert data["severity_breakdown"]["critical"] == 0
    assert data["severity_breakdown"]["low"] == 0

    # Test non-existent scan 404
    missing_id = uuid.uuid4()
    res_404 = await client_with_db.get(f"/api/scans/{missing_id}")
    assert res_404.status_code == 404
    err = res_404.json()
    assert err["error"]["code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_list_scan_findings_and_filters(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="FilterFindingsProject",
        submission_type="code",
        language="python",
        status="completed",
    )
    isolated_test_db.add(scan)

    f1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="a.py",
        start_line=10,
        end_line=12,
        title="Crit",
        severity="critical",
        risk_score=9.5,
        mitigation="m",
        snippet="s",
        status="open",
        source="rule",
    )
    f2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="b.py",
        start_line=20,
        end_line=22,
        title="Med",
        severity="medium",
        risk_score=5.0,
        mitigation="m",
        snippet="s",
        status="fixed",
        source="ml",
    )
    isolated_test_db.add_all([f1, f2])
    await isolated_test_db.commit()

    # List all findings for scan
    res = await client_with_db.get(f"/api/scans/{scan_id}/findings")
    assert res.status_code == 200
    assert len(res.json()) == 2

    # Filter by severity
    res_crit = await client_with_db.get(f"/api/scans/{scan_id}/findings?severity=critical")
    assert len(res_crit.json()) == 1
    assert res_crit.json()[0]["severity"] == "critical"

    # Filter by status
    res_fixed = await client_with_db.get(f"/api/scans/{scan_id}/findings?status=fixed")
    assert len(res_fixed.json()) == 1
    assert res_fixed.json()[0]["status"] == "fixed"

    # Filter by source
    res_ml = await client_with_db.get(f"/api/scans/{scan_id}/findings?source=ml")
    assert len(res_ml.json()) == 1
    assert res_ml.json()[0]["source"] == "ml"

    # 404 for non-existent scan
    res_404 = await client_with_db.get(f"/api/scans/{uuid.uuid4()}/findings")
    assert res_404.status_code == 404
    assert res_404.json()["error"]["code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_finding_detail_and_patch_status(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="FindingDetailApp",
        submission_type="code",
        language="python",
        status="completed",
    )
    mitigation_id = uuid.uuid4()
    mitigation = Mitigation(
        id=mitigation_id,
        canonical_key="rule:B301",
        title="Deserialization remediation",
        remediation_guidance="Do not use pickle",
        code_diff="- pickle.loads(x)\n+ json.loads(x)",
        references_json=["https://owasp.org/A08"],
    )
    finding_id = uuid.uuid4()
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        mitigation_id=mitigation_id,
        file_path="app.py",
        start_line=15,
        end_line=16,
        title="Insecure Deserialization",
        cwe_id="CWE-502",
        owasp="A08:2025-Software or Data Integrity Failures",
        source="both",
        rule_id="B301",
        snippet="pickle.loads(raw)",
        ml_score=0.92,
        severity="high",
        risk_score=8.5,
        mitigation="Do not use pickle",
        status="open",
    )
    isolated_test_db.add_all([scan, mitigation, finding])
    await isolated_test_db.commit()

    # 1. GET /api/findings/{id}
    res_get = await client_with_db.get(f"/api/findings/{finding_id}")
    assert res_get.status_code == 200
    data = res_get.json()
    assert data["id"] == str(finding_id)
    assert data["source"] == "both"
    assert data["ml_score"] == 0.92
    assert data["mitigation_detail"] is not None
    assert data["mitigation_detail"]["id"] == str(mitigation_id)
    assert data["mitigation_detail"]["code_diff"] is not None

    # 2. PATCH /api/findings/{id} to false_positive
    res_patch = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert res_patch.status_code == 200
    patched_data = res_patch.json()
    assert patched_data["status"] == "false_positive"

    # Verify updated in DB
    await isolated_test_db.refresh(finding)
    assert finding.status == "false_positive"

    # 3. PATCH with invalid status -> 422
    res_invalid = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "bogus_status"},
    )
    assert res_invalid.status_code == 422

    # 4. GET & PATCH non-existent finding -> 404
    missing_fid = uuid.uuid4()
    res_get_404 = await client_with_db.get(f"/api/findings/{missing_fid}")
    assert res_get_404.status_code == 404
    assert res_get_404.json()["error"]["code"] == "FINDING_NOT_FOUND"

    res_patch_404 = await client_with_db.patch(
        f"/api/findings/{missing_fid}",
        json={"status": "accepted"},
    )
    assert res_patch_404.status_code == 404
    assert res_patch_404.json()["error"]["code"] == "FINDING_NOT_FOUND"


@pytest.mark.asyncio
async def test_stats_summary_endpoint(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    # 1. First test empty DB behavior
    res_empty = await client_with_db.get("/api/stats/summary")
    assert res_empty.status_code == 200
    empty_data = res_empty.json()
    assert empty_data["total_scans"] == 0
    assert empty_data["total_findings"] == 0
    assert empty_data["average_risk_score"] == 0.0
    assert empty_data["top_cwes"] == []

    # 2. Seed scans and findings
    s1 = Scan(scan_id=uuid.uuid4(), project_name="App1", submission_type="code", language="python", status="completed", risk_score=8.0, findings_count=2)
    s2 = Scan(scan_id=uuid.uuid4(), project_name="App2", submission_type="code", language="python", status="completed", risk_score=4.0, findings_count=1)
    isolated_test_db.add_all([s1, s2])

    f1 = Finding(id=uuid.uuid4(), scan_id=s1.scan_id, file_path="x.py", start_line=1, end_line=2, title="SQLi", cwe_id="CWE-89", severity="high", risk_score=8.0, mitigation="m", snippet="s", status="open", source="rule")
    f2 = Finding(id=uuid.uuid4(), scan_id=s1.scan_id, file_path="y.py", start_line=1, end_line=2, title="SQLi 2", cwe_id="CWE-89", severity="high", risk_score=8.0, mitigation="m", snippet="s", status="open", source="rule")
    f3 = Finding(id=uuid.uuid4(), scan_id=s2.scan_id, file_path="z.py", start_line=1, end_line=2, title="Deserialization", cwe_id="CWE-502", severity="medium", risk_score=4.0, mitigation="m", snippet="s", status="open", source="ml")
    isolated_test_db.add_all([f1, f2, f3])
    await isolated_test_db.commit()

    # 3. Query stats
    res = await client_with_db.get("/api/stats/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_scans"] == 2
    assert data["total_findings"] == 3
    assert data["average_risk_score"] == 6.0
    assert data["severity_distribution"]["high"] == 2
    assert data["severity_distribution"]["medium"] == 1
    assert data["severity_distribution"]["critical"] == 0
    assert len(data["top_cwes"]) == 2
    assert data["top_cwes"][0]["cwe_id"] == "CWE-89"
    assert data["top_cwes"][0]["count"] == 2
    assert data["top_cwes"][1]["cwe_id"] == "CWE-502"
    assert data["top_cwes"][1]["count"] == 1


@pytest.mark.asyncio
async def test_model_info_endpoint(client_with_db: AsyncClient):
    res = await client_with_db.get("/api/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "model_name" in data
    assert "version" in data
    assert "is_stub" in data
    assert "artifacts_present" in data
    assert "artifacts_path" in data
    assert "device" in data
    assert data["status"] in ("ready", "stub_fallback", "load_failed")
