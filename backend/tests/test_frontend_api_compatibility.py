import io
import uuid
import zipfile
from unittest.mock import AsyncMock
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_frontend_health_compatibility(client_with_db: AsyncClient, monkeypatch):
    """Verify /health returns ok: true as expected by frontend Health type."""
    monkeypatch.setattr("app.api.health.check_database_health", AsyncMock(return_value=True))
    res = await client_with_db.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


@pytest.mark.asyncio
async def test_frontend_model_info_and_revert(client_with_db: AsyncClient):
    """Verify /api/model/info provides model_card, eval, and learning structures."""
    res = await client_with_db.get("/api/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "model_card" in data
    assert "eval" in data
    assert "learning" in data
    assert data["model_card"]["threshold"] in (0.50, 0.53)
    assert len(data["eval"]["held_out"]) >= 1

    revert_res = await client_with_db.post("/api/model/revert", json={"version": "0.1.0"})
    assert revert_res.status_code == 200
    assert revert_res.json()["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_frontend_stats_summary_compatibility(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """Verify /api/stats/summary includes all frontend dashboard fields."""
    scan = Scan(
        scan_id=uuid.uuid4(),
        project_name="DemoApp",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=7.5,
        findings_count=2,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.flush()

    f1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan.scan_id,
        file_path="app.py",
        start_line=1,
        end_line=2,
        title="SQL Injection",
        cwe_id="CWE-89",
        owasp="A05:2025-Injection",
        source="rule",
        severity="high",
        risk_score=8.0,
        mitigation="Use ORM",
        snippet="execute(query)",
        status="open",
    )
    f2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan.scan_id,
        file_path="auth.py",
        start_line=5,
        end_line=6,
        title="Zero-day Pattern",
        cwe_id="CWE-502",
        owasp="A08:2025-Software or Data Integrity Failures",
        source="ml",
        severity="critical",
        risk_score=9.5,
        mitigation="Avoid pickle",
        snippet="pickle.loads(tok)",
        status="open",
    )
    isolated_test_db.add_all([f1, f2])
    await isolated_test_db.commit()

    res = await client_with_db.get("/api/stats/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_scans"] >= 1
    assert data["total_findings"] >= 2
    assert "by_severity" in data
    assert data["by_severity"]["critical"] >= 1
    assert "by_source" in data
    assert data["by_source"]["ml"] >= 1
    assert "by_owasp" in data
    assert "novel_count" in data
    assert data["novel_count"] >= 1
    assert "top_findings" in data
    assert len(data["top_findings"]) >= 1
    assert "last_scan" in data
    assert data["last_scan"] is not None
    assert data["last_scan"]["name"] == "DemoApp"


@pytest.mark.asyncio
async def test_frontend_create_scan_shorthands(client_with_db: AsyncClient, monkeypatch):
    """Verify frontend shorthand submissions (code, git, zip-without-project-name)."""
    monkeypatch.setattr("app.api.scans.execute_scan_pipeline", lambda **kw: None)

    # 1. Code paste shorthand {code, filename}
    paste_res = await client_with_db.post("/api/scans", json={"code": "def run(): pass", "filename": "worker.py"})
    assert paste_res.status_code == 202
    paste_data = paste_res.json()
    assert "scan_id" in paste_data
    assert paste_data["project_name"] == "worker.py"
    assert paste_data["submission_type"] == "code"

    # 2. Git shorthand {git_url}
    git_res = await client_with_db.post("/api/scans", json={"git_url": "https://github.com/example-org/sample-backend.git"})
    assert git_res.status_code == 202
    git_data = git_res.json()
    assert "scan_id" in git_data
    assert git_data["submission_type"] == "git"
    assert git_data["project_name"] == "sample-backend"

    # 3. Zip file without project_name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.py", "print('zip upload')")
    buf.seek(0)
    files = {"file": ("my_archive.zip", buf.getvalue(), "application/zip")}
    zip_res = await client_with_db.post("/api/scans", files=files)
    assert zip_res.status_code == 202
    zip_data = zip_res.json()
    assert zip_data["submission_type"] == "zip"
    assert zip_data["project_name"] == "my_archive"


@pytest.mark.asyncio
async def test_frontend_scans_list_and_detail(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """Verify GET /api/scans and GET /api/scans/{id} output all frontend Scan interface fields."""
    sid = uuid.uuid4()
    scan = Scan(
        scan_id=sid,
        project_name="FrontendCompatScan",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=6.2,
        findings_count=1,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.flush()

    f = Finding(
        id=uuid.uuid4(),
        scan_id=sid,
        file_path="main.py",
        start_line=10,
        end_line=12,
        title="Test Bug",
        cwe_id="CWE-78",
        owasp="A05:2025-Injection",
        source="both",
        severity="high",
        risk_score=7.0,
        mitigation="sanitize",
        snippet="os.system(cmd)",
        status="open",
    )
    isolated_test_db.add(f)
    await isolated_test_db.commit()

    # List scans
    list_res = await client_with_db.get("/api/scans")
    assert list_res.status_code == 200
    scans = list_res.json()
    target = next((s for s in scans if s["scan_id"] == str(sid)), None)
    assert target is not None
    assert target["id"] == str(sid)
    assert target["name"] == "FrontendCompatScan"
    assert target["source_type"] == "code"
    assert target["counts_by_severity"]["high"] == 1
    assert "started_at" in target

    # Detail scan
    det_res = await client_with_db.get(f"/api/scans/{sid}")
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert det_data["id"] == str(sid)
    assert det_data["name"] == "FrontendCompatScan"
    assert det_data["counts_by_severity"]["high"] == 1


@pytest.mark.asyncio
async def test_frontend_findings_pagination_envelope(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """Verify findings endpoint returns {items, total} when frontend query parameters are used."""
    sid = uuid.uuid4()
    scan = Scan(
        scan_id=sid,
        project_name="EnvelopeTest",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=5.0,
        findings_count=1,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.flush()

    f = Finding(
        id=uuid.uuid4(),
        scan_id=sid,
        file_path="pkg/search.py",
        start_line=15,
        end_line=18,
        title="Command Execution",
        cwe_id="CWE-78",
        owasp="A05:2025-Injection",
        source="both",
        severity="critical",
        risk_score=9.2,
        mitigation="Use subprocess with shlex",
        snippet="os.system(user_arg)",
        status="open",
    )
    isolated_test_db.add(f)
    await isolated_test_db.commit()

    # 1. Without frontend pagination params: returns list
    res_list = await client_with_db.get(f"/api/scans/{sid}/findings")
    assert res_list.status_code == 200
    assert isinstance(res_list.json(), list)

    # 2. With frontend params (sort and offset): returns {items, total}
    res_env = await client_with_db.get(f"/api/scans/{sid}/findings?sort=-risk_score&offset=0&limit=50")
    assert res_env.status_code == 200
    data = res_env.json()
    assert isinstance(data, dict)
    assert "items" in data
    assert "total" in data
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Command Execution"


@pytest.mark.asyncio
async def test_frontend_scan_diff(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """Verify /api/scans/{id}/diff endpoint returns diff payload."""
    sid1 = uuid.uuid4()
    sid2 = uuid.uuid4()
    scan1 = Scan(
        scan_id=sid1,
        project_name="DiffProject",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=4.0,
        findings_count=1,
    )
    scan2 = Scan(
        scan_id=sid2,
        project_name="DiffProject",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=8.0,
        findings_count=1,
    )
    isolated_test_db.add_all([scan1, scan2])
    await isolated_test_db.commit()

    diff_res = await client_with_db.get(f"/api/scans/{sid2}/diff")
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert "previous_scan_id" in diff_data
    assert "new" in diff_data
    assert "still_open" in diff_data
    assert "resolved" in diff_data
