import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_orm_models_creation_and_relationships(isolated_test_db: AsyncSession):
    """
    Unit test: Verifies ORM model relationships, cascade deletion,
    and field constraints in an isolated database session.
    """
    # 1. Create a Scan
    scan = Scan(
        project_name="DemoApp",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=8.5,
        findings_count=1,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    assert isinstance(scan.scan_id, uuid.UUID)
    assert scan.status == "completed"

    # 2. Create a Canonical Mitigation
    mitigation = Mitigation(
        canonical_key="rule:B301",
        cwe_id="CWE-502",
        rule_id="B301",
        title="Avoid pickle for untrusted input",
        remediation_guidance="Use JSON or Protocol Buffers instead of pickle.",
        references_json=["https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures"],
    )
    isolated_test_db.add(mitigation)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(mitigation)

    assert isinstance(mitigation.id, uuid.UUID)
    assert mitigation.canonical_key == "rule:B301"

    # 3. Create a Finding referencing Scan and Mitigation
    finding = Finding(
        scan_id=scan.scan_id,
        mitigation_id=mitigation.id,
        file_path="services/auth.py",
        start_line=24,
        end_line=26,
        title="Deserialization of Untrusted Data via pickle",
        cwe_id="CWE-502",
        owasp="A08:2025-Software or Data Integrity Failures",
        source="both",
        rule_id="B301",
        snippet="user_payload = pickle.loads(raw_token)",
        ml_score=0.94,
        severity="high",
        risk_score=8.5,
        mitigation="Avoid using pickle with untrusted data.",
        status="open",
    )
    isolated_test_db.add(finding)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(finding)

    finding_id = finding.id
    mitigation_id = mitigation.id
    assert isinstance(finding_id, uuid.UUID)
    assert finding.scan_id == scan.scan_id
    assert finding.mitigation_id == mitigation_id
    assert finding.severity == "high"

    # 4. Test Cascade Deletion on Scan
    await isolated_test_db.delete(scan)
    await isolated_test_db.commit()

    # The finding should be cascade-deleted by foreign key
    result = await isolated_test_db.execute(select(Finding).where(Finding.id == finding_id))
    assert result.scalar_one_or_none() is None

    # The mitigation catalog entry must remain intact
    mit_result = await isolated_test_db.execute(select(Mitigation).where(Mitigation.id == mitigation_id))
    assert mit_result.scalar_one_or_none() is not None
