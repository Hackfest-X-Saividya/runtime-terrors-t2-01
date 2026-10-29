import json
import logging
import os
import shutil
import subprocess
from typing import List

from app.services.analyzers.base import FindingDraft
from app.services.analyzers.owasp_mapper import map_cwe_to_owasp_2025

logger = logging.getLogger("zerosentinel.semgrep")

SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def run_semgrep_analysis(target_dir: str) -> List[FindingDraft]:
    """
    Executes Semgrep static analyzer against the target directory in a subprocess.
    If Semgrep is unavailable on the system, returns an empty list without crashing.
    """
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        logger.info("Semgrep executable not found on system PATH; skipping Semgrep analysis.")
        return []

    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        "auto",
        "--json",
        "-q",
        target_dir,
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
        logger.warning("Semgrep execution timed out after 60s.")
        return []
    except Exception as exc:
        logger.warning("Failed to invoke Semgrep: %s", exc)
        return []

    if not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        logger.warning("Failed to parse Semgrep JSON output: %s", exc)
        return []

    findings: List[FindingDraft] = []
    results = data.get("results", [])

    for item in results:
        extra = item.get("extra", {})
        raw_sev = extra.get("severity", "WARNING").upper()
        severity = SEMGREP_SEVERITY_MAP.get(raw_sev, "medium")
        risk_score = 8.0 if severity == "high" else (5.0 if severity == "medium" else 2.5)

        # CWE metadata from metadata dictionary
        metadata = extra.get("metadata", {})
        cwe_raw = metadata.get("cwe")
        cwe_id = None
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_id = cwe_raw[0].split(":")[0].strip()
        elif isinstance(cwe_raw, str):
            cwe_id = cwe_raw.split(":")[0].strip()

        owasp = map_cwe_to_owasp_2025(cwe_id)

        # File path
        raw_path = item.get("path", "unknown.py")
        try:
            rel_path = os.path.relpath(raw_path, target_dir)
        except ValueError:
            rel_path = os.path.basename(raw_path)

        start = item.get("start", {})
        end = item.get("end", {})
        start_line = start.get("line", 1)
        end_line = end.get("line", start_line)

        rule_id = item.get("check_id", "SEMGREP_RULE")
        title = extra.get("message", "Semgrep security finding")
        snippet = extra.get("lines", "")

        mitigation = (
            f"Remediate {rule_id}: {title} according to {cwe_id or 'standard'} secure coding practices."
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
