import os
import tempfile
import pytest

from app.core.exceptions import IngestionError
from app.services.ingestion.code_ingest import ingest_pasted_code


def test_ingest_pasted_code_valid():
    """Verify valid pasted source code writes correctly into target directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        code = "import pickle\nuser_data = pickle.loads(raw_token)\n"
        rel_path = ingest_pasted_code(code, temp_dir, language="python")

        assert rel_path == "main.py"
        full_path = os.path.join(temp_dir, rel_path)
        assert os.path.exists(full_path)
        with open(full_path, "r", encoding="utf-8") as f:
            assert f.read() == code


def test_ingest_pasted_code_empty():
    """Verify empty or whitespace-only code raises IngestionError."""
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(IngestionError) as exc_info:
            ingest_pasted_code("   \n\t  ", temp_dir)
        assert exc_info.value.code == "EMPTY_SOURCE_CODE"
