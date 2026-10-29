import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_report_html_format(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="PaymentService",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=8.5,
        findings_count=1,
    )
    mit_id = uuid.uuid4()
    mitigation = Mitigation(
        id=mit_id,
        canonical_key="rule:B301",
        title="Deserialization Fix",
        remediation_guidance="Use json instead of pickle.",
        code_diff="- pickle.loads(x)\n+ json.loads(x)",
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        mitigation_id=mit_id,
        file_path="src/auth.py",
        start_line=10,
        end_line=12,
        title="Untrusted Pickle Deserialization",
        severity="high",
        risk_score=8.5,
        mitigation="Use json instead of pickle.",
        snippet="data = pickle.loads(token)",
        status="open",
        source="both",
        cwe_id="CWE-502",
        owasp="A08:2025-Software or Data Integrity Failures",
        rule_id="B301",
        ml_score=0.92,
    )
    isolated_test_db.add_all([scan, mitigation, finding])
    await isolated_test_db.commit()

    # Default format (no query param) defaults to HTML
    res = await client_with_db.get(f"/api/scans/{scan_id}/report")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    html_text = res.text
    assert "<!DOCTYPE html>" in html_text
    assert "PaymentService" in html_text
    assert "Untrusted Pickle Deserialization" in html_text
    assert "CWE-502" in html_text
    assert "A08:2025" in html_text
    assert "pickle.loads" in html_text
    assert "Suggested Remediation Diff" in html_text


@pytest.mark.asyncio
async def test_get_report_html_xss_prevention(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """
    Verifies that malicious or user-crafted finding text is HTML-escaped
    and cannot cause XSS injection in the report.
    """
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="<script>alert('pwned')</script>",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=9.0,
        findings_count=1,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="<img src=x onerror=alert(1)>.py",
        start_line=1,
        end_line=2,
        title="<svg/onload=alert('title')>",
        severity="critical",
        risk_score=9.0,
        mitigation="<b>evil</b>",
        snippet="<script>document.cookie</script>",
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=html")
    assert res.status_code == 200
    html_text = res.text

    # None of the unescaped tags should appear
    assert "<script>alert('pwned')</script>" not in html_text
    assert "<img src=x onerror=alert(1)>" not in html_text
    assert "<svg/onload=alert('title')>" not in html_text
    assert "<script>document.cookie</script>" not in html_text

    # The escaped versions must appear
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html_text or "&lt;script&gt;alert('pwned')&lt;/script&gt;" in html_text
    assert "&lt;script&gt;document.cookie&lt;/script&gt;" in html_text


@pytest.mark.asyncio
async def test_get_report_pdf_format(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="PDFTestApp",
        submission_type="git",
        language="python",
        status="completed",
        risk_score=7.0,
        findings_count=1,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="app/views.py",
        start_line=5,
        end_line=8,
        title="SQL Injection Vulnerability",
        severity="high",
        risk_score=7.0,
        mitigation="Use parameterized queries.",
        snippet="cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
        status="open",
        source="rule",
        cwe_id="CWE-89",
        owasp="A05:2025-Injection",
        rule_id="B608",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert res.status_code == 200
    assert "application/pdf" in res.headers["content-type"]
    assert "Content-Disposition" in res.headers
    assert f"zerosentinel_report_{scan_id}.pdf" in res.headers["Content-Disposition"]

    # Verify PDF magic bytes
    pdf_bytes = res.content
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500


@pytest.mark.asyncio
async def test_get_report_pdf_unicode_and_long_snippets(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    """
    Verifies that ReportLab handles very long lines, special XML characters,
    and Unicode safely without crashing or throwing formatting errors.
    """
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="Unicode & Special Chars: \u2014 \u2022 \u2192",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=4.0,
        findings_count=1,
    )
    long_line = "x = " + ("a" * 200) + " + " + ("b" * 200)
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="unicode_test.py",
        start_line=1,
        end_line=2,
        title="Long Line & XML Entities: <test> & 'quotes' \"double\"",
        severity="medium",
        risk_score=4.0,
        mitigation="Safe mitigation with characters < > &",
        snippet=long_line,
        status="open",
        source="rule",
    )
    isolated_test_db.add_all([scan, finding])
    await isolated_test_db.commit()

    res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_get_report_empty_findings(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="CleanApp",
        submission_type="code",
        language="python",
        status="completed",
        risk_score=0.0,
        findings_count=0,
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()

    # HTML
    res_html = await client_with_db.get(f"/api/scans/{scan_id}/report?format=html")
    assert res_html.status_code == 200
    assert "No Security Vulnerabilities Detected" in res_html.text

    # PDF
    res_pdf = await client_with_db.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.content.startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_get_report_scan_not_found(client_with_db: AsyncClient):
    missing_id = uuid.uuid4()
    res = await client_with_db.get(f"/api/scans/{missing_id}/report?format=html")
    assert res.status_code == 404
    data = res.json()
    assert data["error"]["code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_report_invalid_format(client_with_db: AsyncClient, isolated_test_db: AsyncSession):
    scan_id = uuid.uuid4()
    scan = Scan(
        scan_id=scan_id,
        project_name="App",
        submission_type="code",
        language="python",
        status="completed",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()

    res = await client_with_db.get(f"/api/scans/{scan_id}/report?format=docx")
    assert res.status_code == 400
    data = res.json()
    assert data["error"]["code"] == "INVALID_REPORT_FORMAT"
