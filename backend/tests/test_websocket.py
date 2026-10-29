import asyncio
import uuid
from unittest.mock import AsyncMock
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.testclient import TestClient

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.broadcaster import ScanBroadcaster, broadcaster


def test_ws_invalid_uuid(sync_client_with_db: TestClient):
    with sync_client_with_db.websocket_connect("/ws/scans/not-a-valid-uuid") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["data"]["scan_id"] == "not-a-valid-uuid"
        assert msg["data"]["code"] == "INVALID_SCAN_ID"


def test_ws_scan_not_found(sync_client_with_db: TestClient):
    missing_id = str(uuid.uuid4())
    with sync_client_with_db.websocket_connect(f"/ws/scans/{missing_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["data"]["scan_id"] == missing_id
        assert msg["data"]["code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_ws_completed_scan_immediate_done(
    sync_client_with_db: TestClient,
    isolated_test_db: AsyncSession,
):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="CompletedScanApp",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=7.8,
        findings_count=1,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="Test High",
        severity="high",
        risk_score=7.8,
        mitigation="mit",
        snippet="snip",
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    with sync_client_with_db.websocket_connect(f"/ws/scans/{scan_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "done"
        data = msg["data"]
        assert data["scan_id"] == str(scan_id)
        assert data["status"] == "completed"
        assert data["risk_score"] == 7.8
        assert data["findings_count"] == 1
        assert data["severity_breakdown"]["high"] == 1
        assert data["severity_breakdown"]["critical"] == 0


@pytest.mark.asyncio
async def test_ws_failed_scan_immediate_error(
    sync_client_with_db: TestClient,
    isolated_test_db: AsyncSession,
):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="FailedScanApp",
        submission_type="git",
        language="python",
        status="failed",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()

    with sync_client_with_db.websocket_connect(f"/ws/scans/{scan_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        data = msg["data"]
        assert data["scan_id"] == str(scan_id)
        assert data["code"] == "SCAN_FAILED"


@pytest.mark.asyncio
async def test_ws_active_scan_initial_progress(
    sync_client_with_db: TestClient,
    isolated_test_db: AsyncSession,
):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="ActiveScanApp",
        submission_type="code",
        language="python",
        status="scanning",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()

    with sync_client_with_db.websocket_connect(f"/ws/scans/{scan_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "progress"
        data = msg["data"]
        assert data["scan_id"] == str(scan_id)
        assert data["status"] == "scanning"
        assert "stage" in data
        assert "done" in data
        assert "total" in data


@pytest.mark.asyncio
async def test_broadcaster_event_envelopes_and_payloads():
    """
    Unit test for broadcaster pub/sub logic, testing all four event types:
    - progress
    - finding
    - done
    - error
    Ensures scan_id is strictly included in data payload for every event.
    """
    custom_broadcaster = ScanBroadcaster()
    scan_id = uuid.uuid4()
    mock_ws = AsyncMock()

    await custom_broadcaster.subscribe(scan_id, mock_ws)
    assert scan_id in custom_broadcaster._subscriptions

    # 1. Progress Event
    await custom_broadcaster.publish_progress(
        scan_id=scan_id,
        stage="rules",
        done=2,
        total=4,
        message="Running checks...",
        status="scanning",
    )
    mock_ws.send_json.assert_awaited()
    prog_call = mock_ws.send_json.await_args[0][0]
    assert prog_call["type"] == "progress"
    assert prog_call["data"]["scan_id"] == str(scan_id)
    assert prog_call["data"]["stage"] == "rules"
    assert prog_call["data"]["done"] == 2
    assert prog_call["data"]["total"] == 4

    # 2. Finding Event
    finding_data = {
        "id": str(uuid.uuid4()),
        "file_path": "auth.py",
        "start_line": 10,
        "end_line": 12,
        "title": "Pickle Injection",
        "severity": "high",
        "risk_score": 8.5,
        "mitigation": "Do not use pickle",
        "status": "open",
        "source": "both",
    }
    await custom_broadcaster.publish_finding(scan_id=scan_id, finding_data=finding_data)
    find_call = mock_ws.send_json.await_args[0][0]
    assert find_call["type"] == "finding"
    assert find_call["data"]["scan_id"] == str(scan_id)
    assert find_call["data"]["title"] == "Pickle Injection"

    # 3. Done Event
    await custom_broadcaster.publish_done(
        scan_id=scan_id,
        status="completed",
        risk_score=8.5,
        findings_count=1,
        severity_breakdown={"critical": 0, "high": 1, "medium": 0, "low": 0},
        duration_seconds=1.35,
        completed_at="2026-10-28T12:00:02Z",
    )
    done_call = mock_ws.send_json.await_args[0][0]
    assert done_call["type"] == "done"
    assert done_call["data"]["scan_id"] == str(scan_id)
    assert done_call["data"]["risk_score"] == 8.5
    assert done_call["data"]["severity_breakdown"]["high"] == 1

    # 4. Error Event
    await custom_broadcaster.publish_error(
        scan_id=scan_id,
        code="GIT_CLONE_FAILED",
        message="Clone timed out.",
        stage="ingest",
    )
    err_call = mock_ws.send_json.await_args[0][0]
    assert err_call["type"] == "error"
    assert err_call["data"]["scan_id"] == str(scan_id)
    assert err_call["data"]["code"] == "GIT_CLONE_FAILED"

    # 5. Unsubscribe & cleanup
    await custom_broadcaster.unsubscribe(scan_id, mock_ws)
    assert scan_id not in custom_broadcaster._subscriptions


@pytest.mark.asyncio
async def test_ws_broadcaster_disconnect_cleanup(
    sync_client_with_db: TestClient,
    isolated_test_db: AsyncSession,
):
    """
    Verifies that when a WebSocket client disconnects, the broadcaster
    unsubscribes and frees references, avoiding memory leaks.
    """
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="CleanupScanApp",
        submission_type="code",
        language="python",
        status="scanning",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()

    with sync_client_with_db.websocket_connect(f"/ws/scans/{scan_id}") as ws:
        _ = ws.receive_json()
        assert scan_id in broadcaster._subscriptions
        assert len(broadcaster._subscriptions[scan_id]) == 1

    # After exiting context manager, client has disconnected
    # Allow background server task a brief moment to process the disconnect in finally block
    for _ in range(10):
        if scan_id not in broadcaster._subscriptions or len(broadcaster._subscriptions[scan_id]) == 0:
            break
        await asyncio.sleep(0.05)

    assert scan_id not in broadcaster._subscriptions or len(broadcaster._subscriptions[scan_id]) == 0
