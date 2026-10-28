import os
import sqlite3
import tempfile
import pytest
from alembic import command
from alembic.config import Config

from app.core.config import settings


def test_migration_002_upgrade_and_downgrade(monkeypatch):
    """
    Validates Alembic migration 002_security_frameworks:
    1. Upgrades from clean state to 001_initial_schema on an isolated SQLite database.
    2. Verifies findings table columns before migration 002.
    3. Upgrades to 002_security_frameworks.
    4. Verifies all 6 additive columns are present:
       - cvss_score (Float)
       - cvss_vector (String)
       - cvss_severity (String)
       - cvss_provenance (String, default 'unassessed')
       - security_frameworks (JSON)
       - correlation_data (JSON)
    5. Downgrades back to 001_initial_schema and verifies columns are cleanly removed.
    6. Confirms no remote/live database is touched.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_migration.db").replace("\\", "/")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        # Guarantee test isolation: point settings.DATABASE_URL to local temporary SQLite
        monkeypatch.setattr(settings, "DATABASE_URL", db_url)
        assert "supabase" not in settings.DATABASE_URL
        assert settings.DATABASE_URL.startswith("sqlite")

        alembic_cfg = Config("backend/alembic.ini")
        alembic_cfg.set_main_option("script_location", "backend/alembic")

        # 1. Upgrade to 001_initial_schema
        command.upgrade(alembic_cfg, "001_initial_schema")

        # Inspect table schema using sqlite3 PRAGMA
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(findings)")
        cols_001 = {row[1] for row in cursor.fetchall()}
        conn.close()

        # Prior to 002, the new columns must not exist
        new_cols = {
            "cvss_score",
            "cvss_vector",
            "cvss_severity",
            "cvss_provenance",
            "security_frameworks",
            "correlation_data",
        }
        for col in new_cols:
            assert col not in cols_001, f"Column {col} unexpectedly found in 001 schema."

        # 2. Upgrade to 002_security_frameworks
        command.upgrade(alembic_cfg, "002_security_frameworks")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(findings)")
        cols_002 = {row[1] for row in cursor.fetchall()}
        conn.close()

        # After 002, all 6 columns must exist
        for col in new_cols:
            assert col in cols_002, f"Column {col} missing after 002 upgrade."

        # 3. Downgrade to 001_initial_schema
        command.downgrade(alembic_cfg, "001_initial_schema")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(findings)")
        cols_downgrade = {row[1] for row in cursor.fetchall()}
        conn.close()

        # After downgrade, the columns must be removed
        for col in new_cols:
            assert col not in cols_downgrade, f"Column {col} retained after 002 downgrade."
