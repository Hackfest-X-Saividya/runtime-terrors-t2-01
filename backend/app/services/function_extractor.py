import ast
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("zerosentinel.function_extractor")

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
    "dist",
    "build",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def extract_functions(base_dir: str | Path) -> List[Dict[str, Any]]:
    """
    Safely extracts Python functions from source files in base_dir using AST analysis.
    Zero-execution: source code is parsed with ast.parse and never executed or imported.

    Returns a list of dictionaries conforming to Member 3's detector contract:
    [
        {
            "code": str,
            "file_path": str,  # normalized with forward slashes
            "start_line": int, # 1-indexed
            "end_line": int,   # 1-indexed
            "name": str
        }
    ]
    """
    base_path = Path(base_dir).resolve()
    extracted_functions: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(base_path):
        # Exclude blacklisted directories in-place to prevent descending into them
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]

        for filename in files:
            if not filename.endswith(".py"):
                continue

            full_path = Path(root) / filename
            try:
                stat_res = full_path.stat()
                if stat_res.st_size > MAX_FILE_SIZE:
                    logger.debug("Skipping file %s exceeding size ceiling (%d bytes)", full_path, stat_res.st_size)
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(full_path, base_path).replace("\\", "/")

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    source_text = f.read()
            except Exception as exc:
                logger.warning("Failed to read file %s: %s", rel_path, exc)
                continue

            try:
                tree = ast.parse(source_text, filename=rel_path)
            except SyntaxError as syn_err:
                logger.info("Syntax error in %s at line %s: skipping function extraction for this file.", rel_path, syn_err.lineno)
                continue
            except Exception as exc:
                logger.warning("AST parse failed for %s: %s. Skipping file.", rel_path, exc)
                continue

            lines = source_text.splitlines(keepends=True)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start_line = node.lineno
                    end_line = getattr(node, "end_lineno", node.lineno) or node.lineno

                    # Extract source lines for the function body
                    if 1 <= start_line <= len(lines):
                        func_code = "".join(lines[start_line - 1 : min(end_line, len(lines))])
                    else:
                        func_code = ""

                    extracted_functions.append({
                        "name": node.name,
                        "code": func_code,
                        "file_path": rel_path,
                        "start_line": start_line,
                        "end_line": end_line,
                    })

    return extracted_functions
