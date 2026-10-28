import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan
from app.services.scan_pipeline import execute_scan_pipeline


@pytest.mark.asyncio
async def test_get_scan_findings_serialization_with_frameworks(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
):
    """
    Validates that GET /api/scans/{id}/findings returns enriched Phase 16 fields
    while preserving backward compatibility with existing top-level fields.
    """
    scan = Scan(
        scan_id=uuid.uuid4(),
        project_name="FrameworkApiTest",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=8.5,
        findings_count=1,
    )
    isolated_test_db.add(scan)

    fid = uuid.uuid4()
    finding = Finding(
        id=fid,
        scan_id=scan.scan_id,
        file_path="app/vulnerable.py",
        start_line=15,
        end_line=15,
        title="Command Injection via system shell",
        cwe_id="CWE-78",
        owasp="A05:2025-Injection",
        source="rule",
        rule_id="B605",
        snippet="os.system(user_input)",
        severity="high",
        risk_score=8.5,
        mitigation="Use subprocess with shlex.split and shell=False.",
        status="open",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_severity="CRITICAL",
        cvss_provenance="rule_estimated",
        security_frameworks={
            "owasp_2025": [
                {
                    "version": "2025",
                    "category_id": "A05:2025",
                    "category_name": "Injection",
                    "confidence": "high",
                    "rationale": "Command injection vulnerability.",
                    "primary": True,
                    "cwe_id": "CWE-78",
                }
            ],
            "nist_csf_20": [
                {
                    "version": "2.0",
                    "function_code": "PR",
                    "function_name": "Protect",
                    "category_code": "PR.PS",
                    "category_name": "Platform Security",
                    "subcategory_id": "PR.PS-01",
                    "subcategory_title": "Configuration management",
                    "rationale": "Command injection allows execution outside platform safeguards.",
                    "reference": "NIST CSF 2.0 (Feb 2024)",
                }
            ],
        },
        correlation_data={
            "cluster_id": "a1b2c3d4e5f6",
            "correlation_type": "related_risk",
            "primary_finding_id": str(fid),
            "is_primary": True,
            "confidence": 0.85,
            "rationale": "Static rule match for CWE-78.",
            "evidence": [
                {
                    "source": "rule:B605",
                    "evidence_type": "rule_match",
                    "detail": "Matched pattern on line 15.",
                }
            ],
            "limitations": "Single analyzer source.",
            "related_finding_ids": [],
        },
    )
    isolated_test_db.add(finding)
    await isolated_test_db.commit()

    # 1. Test raw list endpoint
    resp = await client_with_db.get(f"/api/scans/{scan.scan_id}/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    item = data[0]

    # Verify existing contract fields
    assert item["id"] == str(fid)
    assert item["owasp"] == "A05:2025-Injection"
    assert item["risk_score"] == 8.5
    assert item["severity"] == "high"

    # Verify Phase 16 CVSS fields
    assert item["cvss_score"] == 9.8
    assert item["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert item["cvss_severity"] == "CRITICAL"
    assert item["cvss_provenance"] == "rule_estimated"
    assert item["cvss"] is not None
    assert item["cvss"]["version"] == "3.1"
    assert item["cvss"]["score"] == 9.8
    assert item["cvss"]["provenance"] == "rule_estimated"

    # Verify Phase 16 Framework mappings
    assert item["owasp_mappings"] is not None
    assert len(item["owasp_mappings"]) == 1
    assert item["owasp_mappings"][0]["category_id"] == "A05:2025"
    assert item["owasp_mappings"][0]["category_name"] == "Injection"

    assert item["nist_csf_mappings"] is not None
    assert len(item["nist_csf_mappings"]) == 1
    assert item["nist_csf_mappings"][0]["function_code"] == "PR"
    assert item["nist_csf_mappings"][0]["subcategory_id"] == "PR.PS-01"

    # Verify Phase 16 Correlation fields
    assert item["correlation"] is not None
    assert item["correlation"]["cluster_id"] == "a1b2c3d4e5f6"
    assert item["correlation"]["correlation_type"] == "related_risk"
    assert item["correlation"]["is_primary"] is True
    assert len(item["correlation"]["evidence"]) == 1

    # 2. Test pagination envelope format
    resp_paginated = await client_with_db.get(f"/api/scans/{scan.scan_id}/findings?offset=0&limit=10")
    assert resp_paginated.status_code == 200
    pdata = resp_paginated.json()
    assert "items" in pdata
    assert "total" in pdata
    assert pdata["total"] == 1
    p_item = pdata["items"][0]
    assert p_item["cvss"]["score"] == 9.8
    assert p_item["correlation"]["cluster_id"] == "a1b2c3d4e5f6"


@pytest.mark.asyncio
async def test_get_individual_finding_detail(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
):
    """
    Validates GET /api/findings/{id} returns FindingDetailResponse with full framework objects.
    """
    scan = Scan(
        scan_id=uuid.uuid4(),
        project_name="DetailTest",
        submission_type="code",
        language="python",
        status="completed",
    )
    isolated_test_db.add(scan)

    mit = Mitigation(
        id=uuid.uuid4(),
        canonical_key="cwe:CWE-89",
        cwe_id="CWE-89",
        title="Parameterized Queries",
        remediation_guidance="Use bind parameters.",
    )
    isolated_test_db.add(mit)

    fid = uuid.uuid4()
    finding = Finding(
        id=fid,
        scan_id=scan.scan_id,
        mitigation_id=mit.id,
        file_path="app/db.py",
        start_line=20,
        end_line=20,
        title="SQL Injection",
        cwe_id="CWE-89",
        owasp="A05:2025-Injection",
        source="rule",
        snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        severity="critical",
        risk_score=9.5,
        mitigation="Use bind parameters.",
        status="open",
        cvss_score=None,
        cvss_provenance="unassessed",
        security_frameworks={
            "owasp_2025": [
                {
                    "category_id": "A05:2025",
                    "category_name": "Injection",
                    "confidence": "high",
                    "rationale": "Direct SQL injection defect.",
                    "primary": True,
                }
            ]
        },
        correlation_data={
            "cluster_id": "sqlcluster123",
            "correlation_type": "exact_duplicate",
            "is_primary": False,
            "confidence": 0.95,
            "rationale": "Duplicate SQL injection finding.",
        },
    )
    isolated_test_db.add(finding)
    await isolated_test_db.commit()

    resp = await client_with_db.get(f"/api/findings/{fid}")
    assert resp.status_code == 200
    detail = resp.json()

    assert detail["id"] == str(fid)
    assert detail["mitigation_detail"] is not None
    assert detail["mitigation_detail"]["title"] == "Parameterized Queries"

    # Unassessed CVSS defaults
    assert detail["cvss"]["score"] is None
    assert detail["cvss"]["provenance"] == "unassessed"

    # Correlation
    assert detail["correlation"]["cluster_id"] == "sqlcluster123"
    assert detail["correlation"]["is_primary"] is False


@pytest.mark.asyncio
async def test_patch_finding_preserves_frameworks(
    client_with_db: AsyncClient,
    isolated_test_db: AsyncSession,
):
    """
    Validates that updating finding status via PATCH preserves all CVSS, framework, and correlation data.
    """
    scan = Scan(
        scan_id=uuid.uuid4(),
        project_name="PatchTest",
        submission_type="code",
        language="python",
        status="completed",
    )
    isolated_test_db.add(scan)

    fid = uuid.uuid4()
    finding = Finding(
        id=fid,
        scan_id=scan.scan_id,
        file_path="app/auth.py",
        start_line=10,
        end_line=10,
        title="Hardcoded Secret",
        cwe_id="CWE-798",
        owasp="A02:2025-Security Misconfiguration",
        source="rule",
        snippet="SECRET_KEY = 'secret123'",
        severity="medium",
        risk_score=5.0,
        mitigation="Load secret from environment variable.",
        status="open",
        cvss_score=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_severity="MEDIUM",
        cvss_provenance="analyst_assessed",
        security_frameworks={
            "owasp_2025": [
                {
                    "category_id": "A02:2025",
                    "category_name": "Security Misconfiguration",
                    "confidence": "high",
                    "rationale": "Hardcoded key in source.",
                    "primary": True,
                }
            ]
        },
        correlation_data={
            "cluster_id": "cwe798cluster",
            "correlation_type": "related_risk",
            "is_primary": True,
            "confidence": 0.85,
            "rationale": "Single rule detection.",
        },
    )
    isolated_test_db.add(finding)
    await isolated_test_db.commit()

    # PATCH status to 'accepted'
    patch_resp = await client_with_db.patch(
        f"/api/findings/{fid}",
        json={"status": "accepted"},
    )
    assert patch_resp.status_code == 200
    patched_data = patch_resp.json()

    assert patched_data["status"] == "accepted"
    assert patched_data["cvss_score"] == 5.3
    assert patched_data["cvss"]["provenance"] == "analyst_assessed"
    assert patched_data["correlation"]["cluster_id"] == "cwe798cluster"


@pytest.mark.asyncio
async def test_scan_pipeline_end_to_end_framework_integration(
    isolated_test_db: AsyncSession,
):
    """
    Executes scan pipeline end-to-end on vulnerable Python code.
    Verifies that persisted findings have:
    1. OWASP Top 10:2025 mappings
    2. NIST CSF 2.0 mappings
    3. Correlation cluster ID and provenance
    4. Unassessed CVSS defaults (no fabricated scores)
    5. Primary/duplicate status
    """
    scan = Scan(
        project_name="EndToEndPipelineFrameworks",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    code = (
        "import os\n"
        "def run_command(target):\n"
        "    os.system(f'ping -c 1 {target}')\n"
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
    assert scan.findings_count >= 1

    findings_stmt = select(Finding).where(Finding.scan_id == scan.scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) >= 1

    for f in findings:
        # Check backward-compatible top-level fields
        assert f.owasp is not None
        assert "A05:2025" in f.owasp or "Injection" in f.owasp

        # Check CVSS: automated findings must be unassessed, never fabricated
        assert f.cvss_score is None
        assert f.cvss_provenance == "unassessed"

        # Check Frameworks JSON
        assert f.security_frameworks is not None
        assert "owasp_2025" in f.security_frameworks
        assert "nist_csf_20" in f.security_frameworks

        owasp_entries = f.security_frameworks["owasp_2025"]
        assert len(owasp_entries) >= 1
        assert owasp_entries[0]["category_id"] == "A05:2025"
        assert owasp_entries[0]["category_name"] == "Injection"

        nist_entries = f.security_frameworks["nist_csf_20"]
        assert len(nist_entries) >= 1
        assert nist_entries[0]["function_code"] == "PR"
        assert nist_entries[0]["subcategory_id"] == "PR.PS-01"

        # Check Correlation metadata
        assert f.correlation_data is not None
        assert "cluster_id" in f.correlation_data
        assert "correlation_type" in f.correlation_data
        assert "is_primary" in f.correlation_data
        assert f.correlation_data["correlation_type"] in (
            "corroborated",
            "exact_duplicate",
            "related_risk",
            "standalone_candidate",
        )
