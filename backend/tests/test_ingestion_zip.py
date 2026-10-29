import io
import os
import stat
import tempfile
import zipfile
import pytest

from app.core.exceptions import IngestionError, SecurityViolationError
from app.services.ingestion.zip_ingest import validate_and_extract_zip


def _create_zip_buffer(entries: dict) -> io.BytesIO:
    """Helper to create an in-memory zip file from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in entries.items():
            if isinstance(content, str):
                zf.writestr(filename, content.encode("utf-8"))
            elif isinstance(content, zipfile.ZipInfo):
                zf.writestr(content, b"")
            else:
                zf.writestr(filename, content)
    buf.seek(0)
    return buf


def test_zip_valid_extraction():
    """Verify clean ZIP extracts files properly while ignoring excluded directories."""
    entries = {
        "app/main.py": "print('hello')",
        "app/utils.py": "def helper(): pass",
        ".git/config": "hidden git file",
        "node_modules/package.json": "{}",
        "venv/lib/site.py": "pass",
    }
    buf = _create_zip_buffer(entries)

    with tempfile.TemporaryDirectory() as temp_dir:
        count = validate_and_extract_zip(buf, temp_dir)
        assert count == 2  # Only app/main.py and app/utils.py should be extracted
        assert os.path.exists(os.path.join(temp_dir, "app", "main.py"))
        assert os.path.exists(os.path.join(temp_dir, "app", "utils.py"))
        assert not os.path.exists(os.path.join(temp_dir, ".git"))
        assert not os.path.exists(os.path.join(temp_dir, "node_modules"))


def test_zip_path_traversal_dot_dot():
    """Verify rejection of '../' directory traversal in ZIP filenames."""
    buf = _create_zip_buffer({"../../escape.py": "malicious code"})
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "PATH_TRAVERSAL_DETECTED"


def test_zip_windows_style_traversal():
    """Verify rejection of Windows-style '..\\' path traversal."""
    buf = _create_zip_buffer({"..\\..\\win_escape.py": "malicious code"})
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "PATH_TRAVERSAL_DETECTED"


def test_zip_absolute_path_posix():
    """Verify rejection of POSIX absolute paths starting with '/'."""
    buf = _create_zip_buffer({"/etc/passwd": "root:x:0:0"})
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "PATH_TRAVERSAL_DETECTED"


def test_zip_absolute_path_windows():
    """Verify rejection of Windows absolute paths starting with '\\'."""
    buf = _create_zip_buffer({"\\Windows\\System32\\cmd.exe": "payload"})
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "PATH_TRAVERSAL_DETECTED"


def test_zip_drive_letter_path():
    """Verify rejection of Windows drive-letter paths (e.g. C:)."""
    buf = _create_zip_buffer({"C:boot.ini": "payload"})
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "PATH_TRAVERSAL_DETECTED"


def test_zip_symlink_rejection():
    """Verify rejection of symlink entries inside ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zinfo = zipfile.ZipInfo("symlink_entry")
        # Set Unix symlink mode
        zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zinfo, b"/etc/passwd")
    buf.seek(0)

    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "UNSAFE_FILE_TYPE"


def test_zip_entry_count_limit(monkeypatch):
    """Verify rejection when file entry count exceeds threshold."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_ARCHIVE_FILES", 5)

    entries = {f"file_{i}.py": "pass" for i in range(10)}
    buf = _create_zip_buffer(entries)

    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(IngestionError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "ARCHIVE_LIMIT_EXCEEDED"


def test_zip_decompression_bomb_limit(monkeypatch):
    """Verify rejection when uncompressed content exceeds size ceiling."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_UNCOMPRESSED_BYTES", 1000)

    entries = {"big_file.py": "A" * 2000}
    buf = _create_zip_buffer(entries)

    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(IngestionError) as exc_info:
            validate_and_extract_zip(buf, temp_dir)
        assert exc_info.value.code == "DECOMPRESSION_BOMB_DETECTED"
