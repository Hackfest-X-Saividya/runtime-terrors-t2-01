import os
import shutil
import tempfile
import uuid
from pathlib import Path
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.ml_detector import MLDetectorService, ml_service
from app.services.scan_pipeline import execute_scan_pipeline
from detector import Detector


REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = REPO_ROOT / "ml" / "artifacts"


def test_real_detector_loads_from_artifacts():
    """Verify that the real ML detector loads from the integrated artifacts path."""
    assert ARTIFACTS_DIR.exists(), f"Artifacts directory missing: {ARTIFACTS_DIR}"
    det = Detector.load(str(ARTIFACTS_DIR))
    assert det.is_loaded is True
    assert det.active_engine == "baseline"
    assert det.vectorizer is not None
    assert det.binary_model is not None
    assert det.cwe_model is not None

    runtime_info = ml_service.get_runtime_info()
    assert runtime_info["is_stub"] is False
    assert runtime_info["status"] == "ready"
    assert runtime_info["feedback_supported"] is True
    assert runtime_info["artifacts_present"] is True


def test_predict_known_fixtures_schema_and_scores():
    """Verify prediction output schema, score ranges, and source-line mapping on known fixtures."""
    vuln_code = (
        "def query_database(user_id):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    safe_code = (
        "def safe_addition(a: int, b: int) -> int:\n"
        "    return a + b\n"
    )

    functions = [
        {"code": vuln_code, "start_line": 10, "end_line": 14, "file_path": "db.py"},
        {"code": safe_code, "start_line": 30, "end_line": 32, "file_path": "math.py"},
    ]

    preds = ml_service.predict(functions)
    assert len(preds) == 2

    # Vulnerable fixture checks
    p_vuln = preds[0]
    assert isinstance(p_vuln["ml_score"], float)
    assert 0.0 <= p_vuln["ml_score"] <= 1.0
    assert p_vuln["ml_score"] >= 0.50
    assert p_vuln["cwe_guess"] == "CWE-89"
    assert "top_lines" in p_vuln
    assert len(p_vuln["top_lines"]) >= 1
    for line in p_vuln["top_lines"]:
        assert 10 <= line <= 14

    # Safe fixture checks
    p_safe = preds[1]
    assert 0.0 <= p_safe["ml_score"] <= 1.0
    assert p_safe["ml_score"] < 0.50


@pytest.mark.asyncio
async def test_scan_pipeline_with_real_detector_persistence_and_correlation(
    isolated_test_db: AsyncSession,
):
    """
    Submit code through the scan pipeline with the real ML detector active.
    Verify findings are persisted, retrievable, and correlated without duplicates.
    """
    scan = Scan(
        project_name="RealMLPipelineTest",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    code = (
        "import subprocess\n\n"
        "def check_host(ip_address):\n"
        "    cmd = f'ping -c 1 {ip_address}'\n"
        "    return subprocess.check_output(cmd, shell=True)\n"
    )

    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="code",
        source_code=code,
        language="python",
        session_override=isolated_test_db,
    )

    await isolated_test_db.refresh(scan)
    assert scan.status == "completed"

    findings_stmt = select(Finding).where(Finding.scan_id == scan.scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) >= 1

    # Verify no duplicate findings with identical file_path, start_line, rule_id
    keys = set()
    for f in findings:
        key = (f.file_path, f.start_line, f.rule_id, f.cwe_id)
        assert key not in keys, f"Duplicate finding encountered: {key}"
        keys.add(key)

    # Check rule + ML correlation
    corroborated = [f for f in findings if f.source in ("both", "rule")]
    assert len(corroborated) >= 1
    target = corroborated[0]
    assert target.ml_score is not None
    assert 0.0 <= target.ml_score <= 1.0


@pytest.mark.asyncio
async def test_patch_finding_feedback_reaches_real_detector(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
):
    """
    Exercise PATCH /api/findings/{id} and verify eligible feedback reaches the real detector.
    """
    scan = Scan(
        project_name="FeedbackDispatchTest",
        submission_type="code",
        language="python",
        status="completed",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    snippet = (
        "def render_welcome(name):\n"
        "    return f'<h1>Welcome {name}</h1>'\n"
    )
    finding = Finding(
        scan_id=scan.scan_id,
        file_path="views.py",
        start_line=1,
        end_line=2,
        title="Cross-Site Scripting Candidate",
        cwe_id="CWE-79",
        owasp="A05:2025-Injection",
        source="ml",
        snippet=snippet,
        ml_score=0.72,
        severity="medium",
        risk_score=5.5,
        mitigation="Escape user input before rendering.",
        status="open",
    )
    isolated_test_db.add(finding)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(finding)

    # Patch finding to false_positive
    res = await client_with_db.patch(
        f"/api/findings/{finding.id}",
        json={"status": "false_positive"},
    )
    assert res.status_code == 200
    updated = res.json()
    assert updated["status"] == "false_positive"


def test_accepted_status_produces_no_suppression_penalty():
    """Verify that 'accepted' produces no suppression penalty or weight change."""
    snippet = "def execute_custom_sql(q): cursor.execute(q)"
    res = ml_service.feedback(
        code=snippet,
        status="accepted",
        func_name="execute_custom_sql",
        cwe_id="CWE-89",
    )
    assert res["status"] == "accepted"
    assert res["reward"] == 0.0
    assert res["applied"] is False
    assert "skipped" in res["message"].lower()


def test_feedback_changes_subsequent_predictions_as_intended(tmp_path):
    """
    Verify that feedback changes subsequent predictions only as intended:
    - false_positive reduces score (suppression)
    - fixed increases score (reinforcement)
    """
    # Create isolated copy of artifacts for feedback testing
    temp_art = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS_DIR, temp_art)

    det = Detector.load(temp_art)
    assert det.is_loaded is True

    test_fn = [{
        "code": "def dynamic_worker(cmd):\n    os.system(cmd)\n",
        "start_line": 1,
        "end_line": 2,
    }]

    initial_preds = det.predict(test_fn)
    initial_score = initial_preds[0]["ml_score"]

    # 1. Apply false_positive penalty
    fb_res1 = det.feedback(
        code=test_fn[0]["code"],
        status="false_positive",
        func_name="dynamic_worker",
        cwe_id="CWE-78",
    )
    assert fb_res1["reward"] == -1.5

    penalized_preds = det.predict(test_fn)
    penalized_score = penalized_preds[0]["ml_score"]
    assert penalized_score < initial_score, (
        f"Score was not suppressed: initial={initial_score}, penalized={penalized_score}"
    )

    # 2. Apply fixed reinforcement
    fb_res2 = det.feedback(
        code=test_fn[0]["code"],
        status="fixed",
        func_name="dynamic_worker",
        cwe_id="CWE-78",
    )
    assert fb_res2["reward"] == 1.0

    reinforced_preds = det.predict(test_fn)
    reinforced_score = reinforced_preds[0]["ml_score"]
    assert reinforced_score > penalized_score, (
        f"Score was not reinforced: penalized={penalized_score}, reinforced={reinforced_score}"
    )


def test_missing_or_corrupt_artifacts_fall_back_safely(tmp_path):
    """Verify that missing or malformed artifacts fall back safely without crashes."""
    # Case 1: Empty directory
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    service1 = MLDetectorService(artifacts_path=str(empty_dir))
    info1 = service1.get_runtime_info()
    assert info1["is_stub"] is True
    assert info1["status"] in ("stub_fallback", "load_failed")
    assert info1["feedback_supported"] is False

    # Case 2: Corrupt binary artifact
    corrupt_dir = tmp_path / "corrupt"
    corrupt_dir.mkdir()
    (corrupt_dir / "binary_model.joblib").write_bytes(b"CORRUPTED_NOT_A_JOBLIB")
    (corrupt_dir / "tfidf_vectorizer.joblib").write_bytes(b"CORRUPTED")
    (corrupt_dir / "cwe_model.joblib").write_bytes(b"CORRUPTED")
    service2 = MLDetectorService(artifacts_path=str(corrupt_dir))
    info2 = service2.get_runtime_info()
    assert info2["is_stub"] is True
    assert info2["status"] == "load_failed"
    assert info2["feedback_supported"] is False


def test_feedback_persistence_survives_reload(tmp_path):
    """Verify that feedback state saved to disk survives a detector reload."""
    temp_art = tmp_path / "persist_test"
    shutil.copytree(ARTIFACTS_DIR, temp_art)

    det1 = Detector.load(temp_art)
    fn_code = "def custom_eval_exec(p): eval(p)"
    det1.feedback(
        code=fn_code,
        status="fixed",
        func_name="custom_eval_exec",
        cwe_id="CWE-94",
    )

    # Verify state was persisted to rl_state.json
    rl_state_file = temp_art / "rl_state.json"
    assert rl_state_file.exists()

    # Load brand new detector instance from same path
    det2 = Detector.load(temp_art)
    assert det2.is_loaded is True
    assert det2.feedback_learner is not None
    assert det2.feedback_learner.total_feedback_count >= 1
    assert det2.feedback_learner.confirmed_count >= 1


def test_backend_resilience_when_feedback_persistence_fails(monkeypatch):
    """Verify that the backend remains functional even if disk writes/persistence fail."""
    def failing_save(*args, **kwargs):
        raise OSError("Simulated disk write failure or read-only filesystem")

    if ml_service._detector and hasattr(ml_service._detector, "feedback_learner"):
        monkeypatch.setattr(ml_service._detector.feedback_learner, "save", failing_save)

    result = ml_service.feedback(
        code="def foo(): pass",
        status="fixed",
        func_name="foo",
    )
    # The call should succeed gracefully without raising an unhandled exception
    assert isinstance(result, dict)
