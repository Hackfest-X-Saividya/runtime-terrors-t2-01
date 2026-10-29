import os
from app.core.exceptions import IngestionError


def ingest_pasted_code(source_code: str, target_dir: str, language: str = "python") -> str:
    """
    Safely writes a pasted source code snippet into an isolated file within target_dir.
    Returns the relative path of the created file.
    """
    if not source_code or not source_code.strip():
        raise IngestionError("EMPTY_SOURCE_CODE", "Pasted source code must not be empty.")

    # Extension mapping
    ext = ".py" if language.lower() in ("python", "py") else ".txt"
    relative_path = f"main{ext}"
    full_path = os.path.join(target_dir, relative_path)

    try:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(source_code)
    except Exception as exc:
        raise IngestionError("CODE_WRITE_FAILED", f"Failed to write source code: {exc}")

    return relative_path
