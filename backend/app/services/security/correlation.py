import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Set, Tuple


@dataclass(frozen=True)
class CorrelationEvidenceItem:
    """Individual evidence record supporting finding correlation."""
    source: str          # e.g., "rule:bandit:B605", "rule:semgrep:cmd-inj", "ml:tfidf_detector"
    evidence_type: str   # "ast_scope", "cwe_congruence", "token_overlap", "line_proximity"
    detail: str

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "evidence_type": self.evidence_type,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CorrelationResult:
    """Correlation metadata attached to an individual finding."""
    cluster_id: str
    correlation_type: Literal[
        "exact_duplicate",
        "corroborated",
        "related_risk",
        "standalone_candidate",
        "unassigned",
    ]
    primary_finding_id: Optional[str]
    is_primary: bool
    confidence: float
    rationale: str
    evidence: List[CorrelationEvidenceItem] = field(default_factory=list)
    limitations: Optional[str] = None
    related_finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "correlation_type": self.correlation_type,
            "primary_finding_id": self.primary_finding_id,
            "is_primary": self.is_primary,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
            "limitations": self.limitations,
            "related_finding_ids": list(self.related_finding_ids),
        }


@dataclass
class CorrelatedCluster:
    """Cluster grouping related or duplicate findings."""
    cluster_id: str
    primary_finding_id: str
    finding_ids: List[str] = field(default_factory=list)
    cluster_type: Literal["duplicate_group", "corroborated_group", "risk_cluster", "standalone_ml"] = "risk_cluster"
    cwe_family: Optional[str] = None
    file_path: str = ""
    summary: str = ""


def normalize_path(path: str) -> str:
    """Normalizes cross-platform file paths to forward-slash relative strings."""
    if not path:
        return ""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def compute_cluster_id(file_path: str, scope_key: str, cwe_family: Optional[str] = None) -> str:
    """Generates a deterministic 12-char hex cluster identifier."""
    seed = f"{normalize_path(file_path)}:{scope_key}:{cwe_family or 'GENERIC'}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


class CorrelationEngine:
    """
    Explainable Correlation Engine.
    Correlates findings across multiple static rules (Bandit, Semgrep) and ML predictions.
    Distinguishes exact duplicates from corroborated findings and related-but-distinct risks.
    """

    @classmethod
    def are_exact_duplicates(
        cls,
        f1: Dict[str, Any],
        f2: Dict[str, Any],
        line_tolerance: int = 2,
    ) -> Tuple[bool, List[CorrelationEvidenceItem]]:
        """
        Evaluates whether two findings represent the exact same underlying vulnerability defect.
        Requires matching file, strongly overlapping line spans, and matching or congruent CWEs.
        """
        p1 = normalize_path(f1.get("file_path", ""))
        p2 = normalize_path(f2.get("file_path", ""))
        if p1 != p2 or not p1:
            return False, []

        s1, e1 = f1.get("start_line", 0), f1.get("end_line", 0)
        s2, e2 = f2.get("start_line", 0), f2.get("end_line", 0)

        # Check line overlap or proximity
        lines_overlap = not (e1 + line_tolerance < s2 or e2 + line_tolerance < s1)
        if not lines_overlap:
            return False, []

        cwe1 = (f1.get("cwe_id") or "").upper().strip()
        cwe2 = (f2.get("cwe_id") or "").upper().strip()

        evidence: List[CorrelationEvidenceItem] = [
            CorrelationEvidenceItem(
                source=f"{f1.get('source')}:{f1.get('rule_id') or 'unknown'}",
                evidence_type="line_proximity",
                detail=f"Line spans [{s1}-{e1}] and [{s2}-{e2}] overlap in {p1}.",
            )
        ]

        # Same CWE or matching vulnerability class
        if cwe1 and cwe2 and cwe1 == cwe2:
            evidence.append(
                CorrelationEvidenceItem(
                    source=f"rule:{f1.get('rule_id')} vs rule:{f2.get('rule_id')}",
                    evidence_type="cwe_congruence",
                    detail=f"Both rules report matching defect classification {cwe1}.",
                )
            )
            return True, evidence

        # Injections family match (e.g. CWE-78 and CWE-77 both represent command injection)
        inj_cwe = {"CWE-78", "CWE-77", "CWE-89", "CWE-79"}
        if cwe1 in inj_cwe and cwe2 in inj_cwe:
            evidence.append(
                CorrelationEvidenceItem(
                    source="vulnerability_family",
                    evidence_type="cwe_congruence",
                    detail=f"Congruent injection classifications {cwe1} and {cwe2}.",
                )
            )
            return True, evidence

        return False, []

    @classmethod
    def correlate_findings(
        cls,
        findings: List[Dict[str, Any]],
        functions_meta: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[CorrelatedCluster], Dict[str, CorrelationResult]]:
        """
        Correlates a list of findings (static rules + ML predictions).
        Returns:
            - List of CorrelatedCluster instances
            - Dictionary mapping finding_id -> CorrelationResult
        """
        if not findings:
            return [], {}

        finding_map = {str(f.get("id", idx)): f for idx, f in enumerate(findings)}
        processed_ids: Set[str] = set()
        clusters: List[CorrelatedCluster] = []
        correlation_results: Dict[str, CorrelationResult] = {}

        # 1. First pass: Detect exact duplicates between static rules (e.g. Bandit vs Semgrep)
        duplicate_groups: List[List[str]] = []
        ids = list(finding_map.keys())

        for i in range(len(ids)):
            id1 = ids[i]
            if id1 in processed_ids:
                continue

            current_group = [id1]
            f1 = finding_map[id1]

            for j in range(i + 1, len(ids)):
                id2 = ids[j]
                if id2 in processed_ids:
                    continue
                f2 = finding_map[id2]

                is_dup, _ = cls.are_exact_duplicates(f1, f2)
                if is_dup:
                    current_group.append(id2)
                    processed_ids.add(id2)

            if len(current_group) > 1:
                duplicate_groups.append(current_group)
                processed_ids.add(id1)

        # Build clusters for duplicate groups
        for group in duplicate_groups:
            primary_id = group[0]
            f_primary = finding_map[primary_id]
            file_p = normalize_path(f_primary.get("file_path", ""))
            cwe_fam = f_primary.get("cwe_id", "GENERIC")
            cluster_id = compute_cluster_id(file_p, f"lines_{f_primary.get('start_line')}", cwe_fam)

            cluster = CorrelatedCluster(
                cluster_id=cluster_id,
                primary_finding_id=primary_id,
                finding_ids=group,
                cluster_type="duplicate_group",
                cwe_family=cwe_fam,
                file_path=file_p,
                summary=f"Exact duplicate detections for {cwe_fam} in {file_p}:{f_primary.get('start_line')}",
            )
            clusters.append(cluster)

            for fid in group:
                is_p = (fid == primary_id)
                other_ids = [x for x in group if x != fid]
                f_curr = finding_map[fid]
                ev = [
                    CorrelationEvidenceItem(
                        source=f"{f_curr.get('source')}:{f_curr.get('rule_id') or 'engine'}",
                        evidence_type="ast_scope",
                        detail=f"Identical code location {file_p}:{f_curr.get('start_line')}-{f_curr.get('end_line')}",
                    )
                ]
                correlation_results[fid] = CorrelationResult(
                    cluster_id=cluster_id,
                    correlation_type="exact_duplicate",
                    primary_finding_id=primary_id,
                    is_primary=is_p,
                    confidence=0.95,
                    rationale="Static analyzers independently detected the same vulnerability defect at this location.",
                    evidence=ev,
                    limitations="Line spans may vary slightly between AST parsers and regex rules.",
                    related_finding_ids=other_ids,
                )

        # 2. Second pass: Process remaining findings (corroborated, standalone ML, related risks)
        remaining_ids = [fid for fid in ids if fid not in processed_ids]

        # Group remaining by file and function scope if meta available
        for fid in remaining_ids:
            f = finding_map[fid]
            file_p = normalize_path(f.get("file_path", ""))
            source = f.get("source", "rule")
            cwe = f.get("cwe_id", "UNKNOWN")
            s_line = f.get("start_line", 0)

            # Check if this finding is a Corroborated finding (source == 'both')
            if source == "both":
                cluster_id = compute_cluster_id(file_p, f"fn_{s_line}", cwe)
                ev = [
                    CorrelationEvidenceItem(
                        source=f"rule:{f.get('rule_id') or 'static'}",
                        evidence_type="rule_match",
                        detail=f"Static rule matched pattern for {cwe}.",
                    ),
                    CorrelationEvidenceItem(
                        source="ml:detector",
                        evidence_type="ml_corroboration",
                        detail=f"ML detector corroborated vulnerability with score {f.get('ml_score', 'N/A')}.",
                    ),
                ]
                res = CorrelationResult(
                    cluster_id=cluster_id,
                    correlation_type="corroborated",
                    primary_finding_id=fid,
                    is_primary=True,
                    confidence=0.90,
                    rationale="Finding confirmed by both deterministic static rule matching and statistical ML model.",
                    evidence=ev,
                    limitations="Corroboration indicates higher confidence, not absence of false positives.",
                    related_finding_ids=[],
                )
                correlation_results[fid] = res
                clusters.append(
                    CorrelatedCluster(
                        cluster_id=cluster_id,
                        primary_finding_id=fid,
                        finding_ids=[fid],
                        cluster_type="corroborated_group",
                        cwe_family=cwe,
                        file_path=file_p,
                        summary=f"Rule & ML corroborated finding for {cwe} in {file_p}:{s_line}",
                    )
                )

            # Check if Standalone ML candidate (source == 'ml')
            elif source == "ml":
                cluster_id = compute_cluster_id(file_p, f"ml_{s_line}", cwe)
                ev = [
                    CorrelationEvidenceItem(
                        source="ml:detector",
                        evidence_type="statistical_prediction",
                        detail=f"Model flagged candidate function with confidence score {f.get('ml_score', 'N/A')}.",
                    )
                ]
                res = CorrelationResult(
                    cluster_id=cluster_id,
                    correlation_type="standalone_candidate",
                    primary_finding_id=fid,
                    is_primary=True,
                    confidence=float(f.get("ml_score") or 0.70),
                    rationale="Unverified zero-day candidate flagged solely by ML detector without static rule match.",
                    evidence=ev,
                    limitations="ML candidate. Must be reviewed by security analyst; not a confirmed zero-day exploit.",
                    related_finding_ids=[],
                )
                correlation_results[fid] = res
                clusters.append(
                    CorrelatedCluster(
                        cluster_id=cluster_id,
                        primary_finding_id=fid,
                        finding_ids=[fid],
                        cluster_type="standalone_ml",
                        cwe_family=cwe,
                        file_path=file_p,
                        summary=f"Unverified ML zero-day candidate for {cwe} in {file_p}:{s_line}",
                    )
                )

            # Individual static rule (source == 'rule')
            else:
                cluster_id = compute_cluster_id(file_p, f"rule_{s_line}", cwe)
                ev = [
                    CorrelationEvidenceItem(
                        source=f"rule:{f.get('rule_id') or 'static'}",
                        evidence_type="rule_match",
                        detail=f"Deterministic rule matched signature at line {s_line}.",
                    )
                ]
                res = CorrelationResult(
                    cluster_id=cluster_id,
                    correlation_type="related_risk",
                    primary_finding_id=fid,
                    is_primary=True,
                    confidence=0.85,
                    rationale=f"Individual static rule detection for {cwe}.",
                    evidence=ev,
                    limitations="Single analyzer source without secondary corroboration.",
                    related_finding_ids=[],
                )
                correlation_results[fid] = res
                clusters.append(
                    CorrelatedCluster(
                        cluster_id=cluster_id,
                        primary_finding_id=fid,
                        finding_ids=[fid],
                        cluster_type="risk_cluster",
                        cwe_family=cwe,
                        file_path=file_p,
                        summary=f"Static rule finding for {cwe} in {file_p}:{s_line}",
                    )
                )

        return clusters, correlation_results
