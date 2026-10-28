import json
import logging
import os
import shutil
import subprocess
from typing import List

from app.services.analyzers.base import FindingDraft
from app.services.analyzers.owasp_mapper import map_cwe_to_owasp_2025

logger = logging.getLogger("zerosentinel.bandit")

SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

SEVERITY_BASE_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.5,
}


def run_bandit_analysis(target_dir: str) -> List[FindingDraft]:
    """
    Executes Bandit static security analyzer against the target directory in a subprocess.
    Never executes scanned source files.
    Returns normalized FindingDraft objects.
    """
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        # Fall back to active virtualenv path if available
        venv_bin = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".venv", "Scripts", "bandit.exe")
        if os.path.exists(venv_bin):
            bandit_bin = os.path.abspath(venv_bin)
        else:
            logger.warning("Bandit binary not found on PATH or in .venv.")
            return []

    cmd = [
        bandit_bin,
        "-r",
        target_dir,
        "-f",
        "json",
        "-q",
    ]

    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=target_dir,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Bandit execution timed out after 60s.")
        return []
    except Exception as exc:
        logger.warning("Failed to invoke Bandit: %s", exc)
        return []

    # Bandit exits 0 (clean) or 1 (issues found). Exit codes > 1 indicate an error.
    if proc.returncode not in (0, 1):
        logger.warning("Bandit exited with code %s: %s", proc.returncode, proc.stderr)
        return []

    if not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        logger.warning("Failed to parse Bandit JSON output: %s", exc)
        return []

    findings: List[FindingDraft] = []
    results = data.get("results", [])

    for item in results:
        raw_sev = item.get("issue_severity", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(raw_sev, "medium")
        risk_score = SEVERITY_BASE_SCORE.get(severity, 5.0)

        # CWE mapping
        cwe_info = item.get("issue_cwe") or {}
        raw_cwe_id = cwe_info.get("id")
        cwe_id = f"CWE-{raw_cwe_id}" if raw_cwe_id else None
        owasp = map_cwe_to_owasp_2025(cwe_id)

        # File path relative to target_dir
        raw_path = item.get("filename", "unknown.py")
        try:
            rel_path = os.path.relpath(raw_path, target_dir)
        except ValueError:
            rel_path = os.path.basename(raw_path)

        line_num = int(item.get("line_number", 1))
        line_range = item.get("line_range") or [line_num]
        start_line = min(line_range) if line_range else line_num
        end_line = max(line_range) if line_range else line_num

        title = item.get("issue_text", "Potential security issue detected")
        rule_id = item.get("test_id", "BANDIT_RULE")
        snippet = item.get("code", "")

        mitigation = (
            f"Address {title} by validating inputs, using safe library alternatives, "
            f"or adhering to {cwe_id or rule_id} remediation guidelines."
        )

        findings.append(
            FindingDraft(
                file_path=rel_path.replace("\\", "/"),
                start_line=start_line,
                end_line=end_line,
                title=title,
                severity=severity,
                risk_score=risk_score,
                mitigation=mitigation,
                snippet=snippet.strip(),
                cwe_id=cwe_id,
                owasp=owasp,
                source="rule",
                rule_id=rule_id,
            )
        )

    return findings
