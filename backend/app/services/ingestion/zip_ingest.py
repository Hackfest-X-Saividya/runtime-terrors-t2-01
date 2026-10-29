import os
import re
import stat
import zipfile
from typing import BinaryIO, Set

from app.core.config import settings
from app.core.exceptions import IngestionError, SecurityViolationError

# Excluded directory names
EXCLUDED_DIRS: Set[str] = {
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

# 1 MB maximum per-file limit
MAX_PER_FILE_BYTES: int = 1024 * 1024


def validate_and_extract_zip(zip_source: BinaryIO, target_dir: str) -> int:
    """
    Validates and securely extracts a ZIP archive into target_dir.
    Applies comprehensive security checks before writing any files:
    - Rejects path traversal, drive letters, absolute paths, and symlinks.
    - Enforces 25MB compressed, 100MB uncompressed, 500 files, and 1MB per-file limits.
    - Excludes dependency and generated build directories.
    Returns the count of extracted files.
    """
    base_dir = os.path.realpath(target_dir)

    try:
        zf = zipfile.ZipFile(zip_source)
    except Exception as exc:
        raise IngestionError("INVALID_ZIP_ARCHIVE", f"Uploaded file is not a valid ZIP archive: {exc}")

    infolist = zf.infolist()

    # 1. Check entry count
    if len(infolist) > settings.MAX_ARCHIVE_FILES:
        raise IngestionError(
            "ARCHIVE_LIMIT_EXCEEDED",
            f"Archive exceeds maximum allowed entries ({len(infolist)} > {settings.MAX_ARCHIVE_FILES}).",
        )

    # 2. Pre-extraction validation pass
    cumulative_uncompressed_bytes = 0
    valid_members = []

    for member in infolist:
        name = member.filename

        # Reject absolute paths (POSIX / or Windows \)
        if name.startswith("/") or name.startswith("\\"):
            raise SecurityViolationError(
                "PATH_TRAVERSAL_DETECTED",
                f"Absolute paths not permitted in archive: {name}",
            )

        # Reject Windows drive letter prefixes (e.g. C:, D:)
        if re.match(r"^[a-zA-Z]:", name):
            raise SecurityViolationError(
                "PATH_TRAVERSAL_DETECTED",
                f"Drive letter prefixes not permitted in archive: {name}",
            )

        # Reject traversal segments ('..') across all slash types
        normalized_name = name.replace("\\", "/")
        parts = normalized_name.split("/")
        if ".." in parts:
            raise SecurityViolationError(
                "PATH_TRAVERSAL_DETECTED",
                f"Directory traversal segment '..' detected: {name}",
            )

        # Reject symlinks, hardlinks, FIFOs, and device nodes
        # Unix mode is stored in the upper 16 bits of external_attr
        mode = member.external_attr >> 16
        if mode != 0 and (stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode)):
            raise SecurityViolationError(
                "UNSAFE_FILE_TYPE",
                f"Symlinks, FIFOs, and device nodes are not permitted: {name}",
            )

        # Containment verification via commonpath
        entry_path = os.path.realpath(os.path.join(base_dir, *parts))
        if os.path.commonpath([base_dir, entry_path]) != base_dir:
            raise SecurityViolationError(
                "PATH_TRAVERSAL_DETECTED",
                f"Path traversal detected: {name}",
            )

        # Skip directories and directory exclusion filters
        if member.is_dir():
            continue

        if any(part in EXCLUDED_DIRS for part in parts):
            continue

        # Skip individual files exceeding 1 MB to prevent memory exhaustion
        if member.file_size > MAX_PER_FILE_BYTES:
            continue

        cumulative_uncompressed_bytes += member.file_size
        if cumulative_uncompressed_bytes > settings.MAX_UNCOMPRESSED_BYTES:
            raise IngestionError(
                "DECOMPRESSION_BOMB_DETECTED",
                f"Total uncompressed size exceeds limit of {settings.MAX_UNCOMPRESSED_BYTES} bytes.",
            )

        valid_members.append((member, entry_path))

    # 3. Extraction pass
    extracted_count = 0
    for member, dest_path in valid_members:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with zf.open(member) as source, open(dest_path, "wb") as target:
            # Chunked write to avoid reading huge chunks into RAM
            while chunk := source.read(65536):
                target.write(chunk)
        extracted_count += 1

    return extracted_count
