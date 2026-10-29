import pytest
from app.services.security.owasp_2025 import OWASP2025Mapper, OWASP_2025_CATEGORIES
from app.services.security.nist_csf import NISTCSFMapper, NIST_FUNCTIONS, NIST_CSF_VERSION


def test_owasp_2025_categories_coverage():
    """Verify all 10 official OWASP Top 10 (2025) categories are correctly defined."""
    assert len(OWASP_2025_CATEGORIES) == 10
    assert OWASP_2025_CATEGORIES["A01:2025"] == "Broken Access Control"
    assert OWASP_2025_CATEGORIES["A02:2025"] == "Security Misconfiguration"
    assert OWASP_2025_CATEGORIES["A03:2025"] == "Software Supply Chain Failures"
    assert OWASP_2025_CATEGORIES["A04:2025"] == "Cryptographic Failures"
    assert OWASP_2025_CATEGORIES["A05:2025"] == "Injection"
    assert OWASP_2025_CATEGORIES["A06:2025"] == "Insecure Design"
    assert OWASP_2025_CATEGORIES["A07:2025"] == "Authentication Failures"
    assert OWASP_2025_CATEGORIES["A08:2025"] == "Software or Data Integrity Failures"
    assert OWASP_2025_CATEGORIES["A09:2025"] == "Security Logging and Alerting Failures"
    assert OWASP_2025_CATEGORIES["A10:2025"] == "Mishandling of Exceptional Conditions"


def test_owasp_2025_cwe_mappings_evidence():
    """Verify verified CWE mappings produce accurate OWASP 2025 categories with rationales."""
    # 1. SQL Injection -> A05:2025-Injection
    res_sql = OWASP2025Mapper.map_finding(cwe_id="CWE-89")
    assert len(res_sql) == 1
    assert res_sql[0].category_id == "A05:2025"
    assert res_sql[0].label == "A05:2025-Injection"
    assert res_sql[0].confidence == "high"
    assert res_sql[0].primary is True
    assert "SQL" in res_sql[0].rationale

    # 2. Command Injection -> A05:2025-Injection
    res_cmd = OWASP2025Mapper.map_finding(cwe_id="CWE-78")
    assert len(res_cmd) == 1
    assert res_cmd[0].category_id == "A05:2025"

    # 3. Path Traversal -> A01:2025-Broken Access Control
    res_path = OWASP2025Mapper.map_finding(cwe_id="CWE-22")
    assert len(res_path) == 1
    assert res_path[0].category_id == "A01:2025"

    # 4. Multi-mapping: Hardcoded credentials -> A02 primary, A07 secondary
    res_creds = OWASP2025Mapper.map_finding(cwe_id="CWE-798")
    assert len(res_creds) == 2
    assert res_creds[0].category_id == "A02:2025"
    assert res_creds[0].primary is True
    assert res_creds[1].category_id == "A07:2025"
    assert res_creds[1].primary is False

    # 5. Deserialization -> A08:2025
    res_deser = OWASP2025Mapper.map_finding(cwe_id="CWE-502")
    assert len(res_deser) == 1
    assert res_deser[0].category_id == "A08:2025"

    # 6. Supply Chain -> A03:2025
    res_sc = OWASP2025Mapper.map_finding(cwe_id="CWE-1357")
    assert len(res_sc) == 1
    assert res_sc[0].category_id == "A03:2025"

    # 7. Unhandled exceptions -> A10:2025
    res_exc = OWASP2025Mapper.map_finding(cwe_id="CWE-755")
    assert len(res_exc) == 1
    assert res_exc[0].category_id == "A10:2025"


def test_owasp_2025_unmapped_when_insufficient_evidence():
    """Verify that unverified or unknown CWEs return an empty list without forcing a category."""
    res = OWASP2025Mapper.map_finding(cwe_id="CWE-99999")
    assert res == []
    label = OWASP2025Mapper.get_primary_label(res)
    assert label is None

    res_empty = OWASP2025Mapper.map_finding()
    assert res_empty == []


def test_nist_csf_20_functions():
    """Verify official NIST CSF 2.0 core functions."""
    assert len(NIST_FUNCTIONS) == 6
    assert NIST_FUNCTIONS["GV"] == "Govern"
    assert NIST_FUNCTIONS["ID"] == "Identify"
    assert NIST_FUNCTIONS["PR"] == "Protect"
    assert NIST_FUNCTIONS["DE"] == "Detect"
    assert NIST_FUNCTIONS["RS"] == "Respond"
    assert NIST_FUNCTIONS["RC"] == "Recover"


def test_nist_csf_20_defensible_mappings():
    """Verify defensible NIST CSF 2.0 technical mappings."""
    # 1. SQL Injection -> PR.PS-01 (Platform Security)
    mappings_sqli = NISTCSFMapper.map_finding(cwe_id="CWE-89")
    assert len(mappings_sqli) == 1
    m_sqli = mappings_sqli[0]
    assert m_sqli.version == "2.0"
    assert m_sqli.function_code == "PR"
    assert m_sqli.function_name == "Protect"
    assert m_sqli.category_code == "PR.PS"
    assert m_sqli.subcategory_id == "PR.PS-01"
    assert "SQL" in m_sqli.rationale

    # 2. Hardcoded Credentials -> PR.AA-01 (Identity & Access Control)
    mappings_creds = NISTCSFMapper.map_finding(cwe_id="CWE-798")
    assert len(mappings_creds) == 1
    m_creds = mappings_creds[0]
    assert m_creds.category_code == "PR.AA"
    assert m_creds.subcategory_id == "PR.AA-01"

    # 3. Weak Cryptography -> PR.DS-02 (Data Security in transit/cryptography)
    mappings_crypto = NISTCSFMapper.map_finding(cwe_id="CWE-327")
    assert len(mappings_crypto) == 1
    assert mappings_crypto[0].category_code == "PR.DS"
    assert mappings_crypto[0].subcategory_id == "PR.DS-02"

    # 4. Supply Chain Component -> GV.SC-04 (Supply Chain Risk Management)
    mappings_sc = NISTCSFMapper.map_finding(cwe_id="CWE-1357")
    assert len(mappings_sc) == 1
    assert mappings_sc[0].function_code == "GV"
    assert mappings_sc[0].category_code == "GV.SC"
    assert mappings_sc[0].subcategory_id == "GV.SC-04"

    # 5. Unsupported / missing CWE -> returns empty list without inventing controls
    assert NISTCSFMapper.map_finding(cwe_id=None) == []
    assert NISTCSFMapper.map_finding(cwe_id="CWE-99999") == []
