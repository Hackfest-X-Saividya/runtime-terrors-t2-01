import io
import uuid
import zipfile
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_scan_code_success(client_with_db: AsyncClient, monkeypatch):
    """Verify POST /api/scans with code snippet returns 202 Accepted and ScanResponse."""
    # Prevent background task from invoking full external scanner during API route test
    async def mock_execute(*args, **kwargs):
        pass

    monkeypatch.setattr("app.api.scans.execute_scan_pipeline", mock_execute)

    payload = {
        "submission_type": "code",
        "project_name": "AuthService",
        "source_code": "import pickle\nuser = pickle.loads(token)\n",
        "language": "python",
    }
    response = await client_with_db.post("/api/scans", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert uuid.UUID(data["scan_id"])  # Valid UUID
    assert data["project_name"] == "AuthService"
    assert data["submission_type"] == "code"
    assert data["status"] == "queued"
    assert data["risk_score"] == 0.0
    assert data["findings_count"] == 0
    assert "created_at" in data
    assert data["completed_at"] is None


@pytest.mark.asyncio
async def test_create_scan_code_empty_fails(client_with_db: AsyncClient):
    """Verify POST /api/scans with empty source_code returns 400 Bad Request with error envelope."""
    payload = {
        "submission_type": "code",
        "project_name": "AuthService",
        "source_code": "   ",
        "language": "python",
    }
    response = await client_with_db.post("/api/scans", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_PAYLOAD"


@pytest.mark.asyncio
async def test_create_scan_git_success(client_with_db: AsyncClient, monkeypatch):
    """Verify POST /api/scans with valid Git URL returns 202 Accepted."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.4", 443))])
    monkeypatch.setattr("app.api.scans.execute_scan_pipeline", lambda *args, **kwargs: None)

    payload = {
        "submission_type": "git",
        "project_name": "GitTestRepo",
        "git_url": "https://github.com/example-org/sample-backend.git",
        "branch": "main",
    }
    response = await client_with_db.post("/api/scans", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["submission_type"] == "git"
    assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_create_scan_git_disallowed_domain(client_with_db: AsyncClient):
    """Verify POST /api/scans with non-allowlisted domain returns 400 with DISALLOWED_DOMAIN."""
    payload = {
        "submission_type": "git",
        "project_name": "GitTestRepo",
        "git_url": "https://malicious-domain.com/repo.git",
        "branch": "main",
    }
    response = await client_with_db.post("/api/scans", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "DISALLOWED_DOMAIN"


@pytest.mark.asyncio
async def test_create_scan_git_invalid_branch(client_with_db: AsyncClient, monkeypatch):
    """Verify POST /api/scans with option-injection branch returns 400 with INVALID_BRANCH_NAME."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.4", 443))])

    payload = {
        "submission_type": "git",
        "project_name": "GitTestRepo",
        "git_url": "https://github.com/org/repo.git",
        "branch": "--upload-pack=touch /tmp/pwn",
    }
    response = await client_with_db.post("/api/scans", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "INVALID_BRANCH_NAME"


@pytest.mark.asyncio
async def test_create_scan_zip_success(client_with_db: AsyncClient, monkeypatch):
    """Verify POST /api/scans with ZIP file upload returns 202 Accepted."""
    monkeypatch.setattr("app.api.scans.execute_scan_pipeline", lambda *args, **kwargs: None)

    # Create dummy ZIP in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "print('hello')")
    buf.seek(0)

    files = {"file": ("archive.zip", buf.getvalue(), "application/zip")}
    data = {
        "submission_type": "zip",
        "project_name": "ZipProject",
        "language": "python",
    }
    response = await client_with_db.post("/api/scans", data=data, files=files)
    assert response.status_code == 202
    res_data = response.json()
    assert res_data["submission_type"] == "zip"
    assert res_data["project_name"] == "ZipProject"
    assert res_data["status"] == "queued"


@pytest.mark.asyncio
async def test_create_scan_zip_missing_project_name(client_with_db: AsyncClient):
    """Verify POST /api/scans with missing project_name returns 400 with MISSING_PROJECT_NAME."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "print('hello')")
    buf.seek(0)

    files = {"file": ("archive.zip", buf.getvalue(), "application/zip")}
    data = {"submission_type": "zip"}  # Missing project_name
    response = await client_with_db.post("/api/scans", data=data, files=files)
    assert response.status_code == 400
    res_data = response.json()
    assert res_data["error"]["code"] == "MISSING_PROJECT_NAME"


@pytest.mark.asyncio
async def test_create_scan_zip_missing_file(client_with_db: AsyncClient):
    """Verify POST /api/scans with missing file returns 400 with MISSING_FILE."""
    data = {
        "submission_type": "zip",
        "project_name": "ZipProject",
    }
    response = await client_with_db.post("/api/scans", data=data)
    assert response.status_code == 400
    res_data = response.json()
    assert res_data["error"]["code"] == "MISSING_FILE"
