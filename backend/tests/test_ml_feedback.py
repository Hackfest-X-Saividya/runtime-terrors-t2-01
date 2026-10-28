import asyncio
import concurrent.futures
import subprocess
import uuid
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.ml_detector import MLDetectorService, MLDetectorStub, ml_service


def test_feedback_stub_fallback_does_not_learn():
    """Verify stub fallback explicitly reports applied=False and does not pretend to learn."""
    stub = MLDetectorStub()
    res = stub.feedback(code="import pickle\npickle.loads(data)", status="false_positive")
    assert res["applied"] is False
    assert res["reward"] == 0.0
    assert "heuristic stub without trainable artifacts" in res["message"]


def test_feedback_semantic_mapping_policies():
    """
    Verify Phase 7B semantic policies:
    - 'accepted' is NOT treated as a negative reward / false positive (skipped to prevent false suppression).
    - 'open' or unrecognized statuses are skipped.
    - Empty code snippets are skipped.
    """
    service = MLDetectorService(artifacts_path="nonexistent")

    # 1. 'accepted' status
    res_accepted = service.feedback(code="def handle_risk(): pass", status="accepted")
    assert res_accepted["applied"] is False
    assert "accepted" in res_accepted["message"].lower()

    # 2. 'open' or unrecognized
    res_open = service.feedback(code="def handle_open(): pass", status="open")
    assert res_open["applied"] is False

    res_invalid = service.feedback(code="def handle_unknown(): pass", status="not_a_valid_status")
    assert res_invalid["applied"] is False

    # 3. Empty snippet
    res_empty = service.feedback(code="   ", status="false_positive")
    assert res_empty["applied"] is False
    assert "empty code snippet" in res_empty["message"]


def test_feedback_with_valid_detector(tmp_path):
    """
    Verify that when a real detector is loaded, MLDetectorService correctly
    dispatches 'false_positive' and 'fixed' while marking feedback_supported=True.
    """
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir()
    (art_dir / "weights.bin").write_text("model weights")

    feedback_mock = MagicMock(return_value={
        "step": 1,
        "status": "false_positive",
        "reward": -1.5,
        "score_before": 0.85,
        "score_after": 0.35,
    })

    class MockDetectorWithFeedback:
        @classmethod
        def load(cls, path):
            return cls()

        def predict(self, functions):
            return []

        def feedback(self, code, status, func_name="unknown"):
            return feedback_mock(code=code, status=status, func_name=func_name)

    import sys
    import types
    mock_mod = types.ModuleType("detector")
    mock_mod.Detector = MockDetectorWithFeedback
    sys.modules["detector"] = mock_mod

    service = MLDetectorService(artifacts_path=str(art_dir))
    assert service.is_stub is False
    assert service.feedback_supported is True

    # Dispatch false positive
    fp_res = service.feedback(code="def search(): pass", status="false_positive", func_name="search")
    assert fp_res["applied"] is True
    assert fp_res["reward"] == -1.5
    feedback_mock.assert_called_with(code="def search(): pass", status="false_positive", func_name="search")

    # Dispatch fixed
    feedback_mock.return_value = {"step": 2, "status": "fixed", "reward": 1.0}
    fixed_res = service.feedback(code="def fixed_query(): pass", status="fixed", func_name="fixed_query")
    assert fixed_res["applied"] is True
    assert fixed_res["reward"] == 1.0


@pytest.mark.asyncio
async def test_patch_finding_dispatches_feedback_on_triage(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
    monkeypatch,
):
    """
    Verify PATCH /api/findings/{id} commits status update to DB and enqueues
    feedback for false_positive.
    """
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="FeedbackTest",
        submission_type="code",
        language="python",
        status="completed",
    )
    finding_id = uuid.uuid4()
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="Test Finding",
        severity="high",
        risk_score=8.0,
        mitigation="Fix it",
        snippet="import pickle\npickle.loads(token)",
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    feedback_called = []

    def mock_feedback(code, status, func_name="unknown"):
        feedback_called.append({"code": code, "status": status, "func_name": func_name})
        return {"applied": True}

    monkeypatch.setattr(ml_service, "feedback", mock_feedback)

    res = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "false_positive"

    # Database verification
    stmt = select(Finding).where(Finding.id == finding_id)
    updated = (await isolated_test_db.execute(stmt)).scalar_one()
    assert updated.status == "false_positive"

    # Feedback verification
    assert len(feedback_called) == 1
    assert feedback_called[0]["status"] == "false_positive"
    assert "pickle.loads" in feedback_called[0]["code"]


@pytest.mark.asyncio
async def test_patch_finding_duplicate_status_prevents_runaway_feedback(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
    monkeypatch,
):
    """
    Verify that calling PATCH /api/findings/{id} with the SAME status that is already set
    does NOT trigger repeated feedback penalty loops.
    """
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    scan = Scan(scan_id=scan_id, project_name="DupTest", submission_type="code", language="python", status="completed")
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="Test Finding",
        severity="high",
        risk_score=8.0,
        mitigation="Fix it",
        snippet="import pickle\npickle.loads(token)",
        status="false_positive",  # Already false_positive
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    feedback_called = []
    monkeypatch.setattr(ml_service, "feedback", lambda *args, **kwargs: feedback_called.append(kwargs))

    # Send repeated PATCH with the exact same status
    res = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert res.status_code == 200
    assert len(feedback_called) == 0  # No duplicate feedback dispatched


@pytest.mark.asyncio
async def test_patch_finding_missing_snippet_skips_feedback(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
    monkeypatch,
):
    """Verify findings without snippet code skip feedback dispatch cleanly."""
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    scan = Scan(scan_id=scan_id, project_name="NoSnippetTest", submission_type="code", language="python", status="completed")
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="No Snippet",
        severity="low",
        risk_score=2.0,
        mitigation="Fix",
        snippet="   ",  # Whitespace only
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    feedback_called = []
    monkeypatch.setattr(ml_service, "feedback", lambda *args, **kwargs: feedback_called.append(kwargs))

    res = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert res.status_code == 200
    assert len(feedback_called) == 0


@pytest.mark.asyncio
async def test_detector_feedback_exception_leaves_db_triage_intact(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
    monkeypatch,
):
    """
    Verify that if the detector feedback raises an unexpected exception (e.g. disk write failure),
    the HTTP request still succeeds and the database update remains committed.
    """
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    scan = Scan(scan_id=scan_id, project_name="ExcTest", submission_type="code", language="python", status="completed")
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        file_path="main.py",
        start_line=1,
        end_line=2,
        title="Exc Finding",
        severity="high",
        risk_score=7.0,
        mitigation="Fix",
        snippet="pickle.loads(x)",
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    def failing_feedback(*args, **kwargs):
        raise OSError("Simulated disk write failure: read-only filesystem")

    monkeypatch.setattr(ml_service, "feedback", failing_feedback)

    res = await client_with_db.patch(
        f"/api/findings/{finding_id}",
        json={"status": "fixed"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "fixed"

    # Database state must be successfully updated
    stmt = select(Finding).where(Finding.id == finding_id)
    updated = (await isolated_test_db.execute(stmt)).scalar_one()
    assert updated.status == "fixed"


@pytest.mark.asyncio
async def test_db_update_failure_does_not_dispatch_feedback(
    client_with_db: AsyncClient,
    monkeypatch,
):
    """Verify that if DB update fails (e.g. 404 finding not found), feedback is never called."""
    feedback_called = []
    monkeypatch.setattr(ml_service, "feedback", lambda *args, **kwargs: feedback_called.append(kwargs))

    missing_id = uuid.uuid4()
    res = await client_with_db.patch(
        f"/api/findings/{missing_id}",
        json={"status": "false_positive"},
    )
    assert res.status_code == 404
    assert len(feedback_called) == 0


def test_concurrent_feedback_requests_thread_safe(tmp_path):
    """
    Verify that concurrent feedback calls are thread-safe and properly serialized
    by MLDetectorService's lock.
    """
    calls = []

    class SlowDetector:
        def feedback(self, code, status, func_name="unknown"):
            import time
            time.sleep(0.01)
            calls.append(func_name)
            return {"applied": True, "func_name": func_name}

    service = MLDetectorService(artifacts_path="dummy")
    service._detector = SlowDetector()
    service.is_stub = False
    service.feedback_supported = True

    def worker(i):
        return service.feedback(code=f"def f{i}(): pass", status="false_positive", func_name=f"f{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker, i) for i in range(10)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 10
    assert all(r["applied"] is True for r in results)
    assert len(calls) == 10


@pytest.mark.asyncio
async def test_model_info_reports_feedback_supported(client_with_db: AsyncClient):
    """Verify GET /api/model/info reports feedback_supported status."""
    res = await client_with_db.get("/api/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "feedback_supported" in data
    assert data["feedback_supported"] is False  # Stub fallback has no feedback learning


def test_no_model_state_tracked_in_git():
    """Verify that rl_state.json is explicitly ignored and untracked."""
    proc = subprocess.run(
        ["git", "check-ignore", "ml/artifacts/rl_state.json"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "rl_state.json" in proc.stdout
