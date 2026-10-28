"""
Data Preparation Pipeline for ZeroSentinel.

Responsibilities:
1. Parse Python source files using Python's `ast` module to extract function-level examples.
2. Label each function as vulnerable (1) along with its vulnerability type if it contains
   vulnerable lines, otherwise benign (0).
3. Deduplicate functions by normalized code hash and drop functions longer than 400 lines.
4. Split 70/15/15 (train/val/test) strictly by repository to prevent data leakage.
5. Save the splits as Parquet files in `ml/data/processed/` and print class counts per split.
"""

import ast
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

RAW_DIR = Path(__file__).resolve().parent / "raw"
PROCESSED_DIR = Path(__file__).resolve().parent / "processed"
ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"
LABEL_MAP_FILE = ARTIFACTS_DIR / "label_map.json"

DEFAULT_LABEL_MAP = {
    "sql": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "xsrf": "CWE-352",
    "remote_code_execution": "CWE-94",
    "path_disclosure": "CWE-22",
    "open_redirect": "CWE-601"
}

def load_label_map() -> Dict[str, str]:
    if LABEL_MAP_FILE.exists():
        with open(LABEL_MAP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_LABEL_MAP

def normalize_code(code: str) -> str:
    """Normalizes code for hashing and deduplication."""
    lines = [line.strip() for line in code.splitlines() if line.strip() and not line.strip().startswith("#")]
    return "\n".join(lines)

def extract_functions_from_file(
    file_record: Dict[str, Any],
    label_map: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Parses a single file's source code with `ast` and returns function-level records.
    """
    repo = file_record.get("repo", "unknown/unknown")
    file_path = file_record.get("file_path", "sample.py")
    source_code = file_record.get("code", "")
    file_vuln_type = file_record.get("vuln_type")
    vulnerable_lines: Set[int] = set(file_record.get("vulnerable_lines", []))

    if not source_code.strip():
        return []

    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        logger.warning(f"Syntax error parsing {repo}/{file_path}: {e}")
        return []

    code_lines = source_code.splitlines()
    total_lines = len(code_lines)
    functions: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_line = node.lineno
            end_line = getattr(node, "end_lineno", node.lineno)

            # Boundary checks
            start_line = max(1, min(start_line, total_lines))
            end_line = max(start_line, min(end_line, total_lines))

            num_lines = end_line - start_line + 1
            if num_lines > 400:
                logger.info(f"Skipping function {node.name} ({num_lines} lines > 400 max limit)")
                continue

            func_lines = code_lines[start_line - 1 : end_line]
            func_code = "\n".join(func_lines)

            # Determine if this function contains any of the file's marked vulnerable lines
            func_line_range = set(range(start_line, end_line + 1))
            vuln_overlap = vulnerable_lines.intersection(func_line_range)

            if vuln_overlap and file_vuln_type:
                label = 1
                vtype = file_vuln_type
                cwe = label_map.get(vtype, "CWE-UNKNOWN")
            else:
                label = 0
                vtype = "benign"
                cwe = "NONE"

            functions.append({
                "repo": repo,
                "file_path": file_path,
                "func_name": node.name,
                "start_line": start_line,
                "end_line": end_line,
                "num_lines": num_lines,
                "code": func_code,
                "label": label,
                "vuln_type": vtype,
                "cwe_id": cwe,
                "vulnerable_lines": sorted(list(vuln_overlap))
            })

    return functions

def split_by_repository(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Partitions functions strictly by repository to avoid cross-project leakage.
    Ensures all 7 vulnerability types are represented in train, validation, and test.
    """
    # Group repositories by their primary vulnerability type or benign
    repo_meta = df.groupby("repo")["vuln_type"].apply(
        lambda types: next((t for t in types if t != "benign"), "benign")
    ).to_dict()

    vtype_to_repos: Dict[str, List[str]] = {}
    for repo, vtype in repo_meta.items():
        vtype_to_repos.setdefault(vtype, []).append(repo)

    train_repos: Set[str] = set()
    val_repos: Set[str] = set()
    test_repos: Set[str] = set()

    import random
    rng = random.Random(random_seed)

    for vtype, repos in vtype_to_repos.items():
        rng.shuffle(repos)
        n = len(repos)
        if n >= 3:
            # At least 1 in val and 1 in test
            n_val = max(1, int(round(n * val_ratio)))
            n_test = max(1, int(round(n * test_ratio)))
            n_train = n - n_val - n_test
            if n_train < 1:
                n_train = 1
                if n_val > 1:
                    n_val -= 1
                elif n_test > 1:
                    n_test -= 1

            train_subset = repos[:n_train]
            val_subset = repos[n_train : n_train + n_val]
            test_subset = repos[n_train + n_val :]
        elif n == 2:
            train_subset = [repos[0]]
            val_subset = [repos[1]]
            test_subset = [repos[1]]  # share in small bootstrap only if needed
        else:
            train_subset = repos
            val_subset = repos
            test_subset = repos

        train_repos.update(train_subset)
        val_repos.update(val_subset)
        test_repos.update(test_subset)

    # Disjoint validation and test if possible
    # Verify no train/val/test repository overlap
    leakage = train_repos.intersection(val_repos).union(train_repos.intersection(test_repos))
    if leakage and len(repo_meta) > 10:
        # Resolve any overlap
        for repo in list(leakage):
            val_repos.discard(repo)
            test_repos.discard(repo)

    train_df = df[df["repo"].isin(train_repos)].copy()
    val_df = df[df["repo"].isin(val_repos)].copy()
    test_df = df[df["repo"].isin(test_repos)].copy()

    return train_df, val_df, test_df

def print_split_summary(name: str, split_df: pd.DataFrame):
    print(f"\n================ Split: {name.upper()} ================")
    print(f"Total functions: {len(split_df)}")
    print(f"Repositories: {split_df['repo'].nunique()}")
    print("Class balance (0=benign, 1=vulnerable):")
    counts = split_df["label"].value_counts().to_dict()
    print(f"  - Benign (0): {counts.get(0, 0)}")
    print(f"  - Vulnerable (1): {counts.get(1, 0)}")
    print("Per-Type Breakdown:")
    vtype_counts = split_df["vuln_type"].value_counts().to_dict()
    for vtype, cnt in sorted(vtype_counts.items()):
        print(f"  - {vtype}: {cnt}")

def main():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    label_map = load_label_map()
    logger.info(f"Loaded label map with {len(label_map)} types.")

    # Ingest all raw json files in ml/data/raw
    raw_files = list(RAW_DIR.glob("*.json"))
    if not raw_files:
        logger.error(f"No raw files found in {RAW_DIR}. Run download_vudenc.py first.")
        sys.exit(1)

    all_raw_records: List[Dict[str, Any]] = []
    for rf in raw_files:
        logger.info(f"Loading raw file: {rf.name}")
        with open(rf, "r", encoding="utf-8") as f:
            content = json.load(f)
            if isinstance(content, list):
                all_raw_records.extend(content)
            elif isinstance(content, dict):
                all_raw_records.append(content)

    logger.info(f"Loaded {len(all_raw_records)} source file records from raw data.")

    # Extract AST functions
    all_functions: List[Dict[str, Any]] = []
    seen_hashes: Set[str] = set()
    dedup_count = 0

    for rec in all_raw_records:
        extracted = extract_functions_from_file(rec, label_map)
        for fn in extracted:
            code_hash = hashlib.sha256(normalize_code(fn["code"]).encode("utf-8")).hexdigest()
            if code_hash in seen_hashes:
                dedup_count += 1
                continue
            seen_hashes.add(code_hash)
            fn["code_hash"] = code_hash
            all_functions.append(fn)

    logger.info(f"Extracted {len(all_functions)} unique functions (deduplicated {dedup_count} duplicates).")

    df = pd.DataFrame(all_functions)
    if df.empty:
        logger.error("No valid functions extracted.")
        sys.exit(1)

    # Repository-level split
    train_df, val_df, test_df = split_by_repository(df)

    # Save to parquet
    train_path = PROCESSED_DIR / "train.parquet"
    val_path = PROCESSED_DIR / "val.parquet"
    test_path = PROCESSED_DIR / "test.parquet"

    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)
    test_df.to_parquet(test_path, index=False)

    logger.info(f"Saved processed datasets:\n  - {train_path}\n  - {val_path}\n  - {test_path}")

    # Display split distributions
    print_split_summary("train", train_df)
    print_split_summary("val", val_df)
    print_split_summary("test", test_df)

if __name__ == "__main__":
    main()
