"""
ZeroSentinel Demo Target: Vulnerability Sample File.

Contains:
1. Standard 'Confirmed' Vulnerabilities:
   - Classic SQL injection, Command Injection, and XSS patterns that are caught
     by both static analysis rules (Bandit/Semgrep) and the ML detector.
2. Subtle 'Novel' Vulnerabilities (Zero-Day Candidates):
   - Obfuscated dynamic SQL assembly, reflection-based deserialization, and
     multi-tier unvalidated path handling that slip past traditional static AST
     rules, but are flagged by our ML detector.
3. Benign Control Functions:
   - Properly parameterized queries, safe subprocess calls, and cryptographic utilities.
"""

import hashlib
import os
import subprocess
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
db_conn = sqlite3.connect(":memory:", check_same_thread=False)

# ==============================================================================
# SECTION 1: CONFIRMED FINDINGS (Caught by Static Rules AND ML Detector)
# ==============================================================================

def search_users_classic():
    """
    CONFIRMED: Classic SQL Injection (CWE-89)
    Triggers Bandit B608 and Semgrep python.lang.security.audit.sqli
    """
    username = request.args.get("username", "")
    cursor = db_conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def execute_system_ping():
    """
    CONFIRMED: OS Command Injection (CWE-78)
    Triggers Bandit B602 (subprocess with shell=True) and Semgrep
    """
    target_host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 2 {target_host}"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode("utf-8")

def render_user_profile():
    """
    CONFIRMED: Cross-Site Scripting (CWE-79)
    Triggers Semgrep direct template rendering of untrusted string
    """
    bio_html = request.args.get("bio", "Default bio")
    template = f"<div class='profile-card'>{bio_html}</div>"
    return render_template_string(template)

# ==============================================================================
# SECTION 2: NOVEL FINDINGS (Missed by Static Rules, Caught by ML Detector)
# ==============================================================================

def dynamic_query_assembler():
    """
    NOVEL (Zero-Day Candidate): Dynamic Query Builder (CWE-89)
    Slips past standard Bandit AST rules because cursor.execute receives a clean
    pre-assembled variable rather than a literal string interpolation at call site.
    Flagged by ZeroSentinel ML as high risk due to unvalidated request parameter flow.
    """
    table = request.args.get("table", "products")
    filter_field = request.args.get("field", "title")
    filter_val = request.args.get("val", "")
    
    # Assembled across multiple statements and dict buffers
    query_parts = ["SELECT", "*", "FROM", table, "WHERE", filter_field, "=", f"'{filter_val}'"]
    raw_statement = " ".join(query_parts)
    
    cursor = db_conn.cursor()
    cursor.execute(raw_statement)
    return cursor.fetchall()

def dispatch_dynamic_worker():
    """
    NOVEL (Zero-Day Candidate): Dynamic Deserialization / RCE (CWE-94)
    Slips past static pattern scanners that look for 'pickle.loads' imports by
    resolving the loader dynamically via reflection from runtime modules.
    Flagged by ZeroSentinel ML due to untrusted form data deserialization pattern.
    """
    raw_payload = request.form.get("task_blob", "")
    import base64
    blob = base64.b64decode(raw_payload)
    # Indirect function resolution avoids static regex on 'pickle.loads'
    loader = getattr(__import__("pickle"), "loads")
    task_instance = loader(blob)
    return task_instance()

def stream_tenant_log():
    """
    NOVEL (Zero-Day Candidate): Multi-Tier Path Traversal (CWE-22)
    Bypasses simple single-parameter regex checks by composing multi-segment
    tenant directory hierarchies without absolute path boundaries.
    """
    tenant_id = request.args.get("tenant", "default")
    log_name = request.args.get("log", "app.log")
    file_path = f"/var/log/tenants/{tenant_id}/{log_name}"
    with open(file_path, "r", encoding="utf-8") as f:
        return f.readlines()

# ==============================================================================
# SECTION 3: BENIGN CONTROLS (Clean Code, Neither Rules Nor ML Should Flag)
# ==============================================================================

def safe_get_user_by_id(user_id: int):
    """
    BENIGN: Secure Parameterized SQL Query
    Uses safe DB-API parameter tuples.
    """
    cursor = db_conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

def safe_run_ping(host: str):
    """
    BENIGN: Safe Subprocess Execution
    Executes binary without shell=True, passing arguments as a fixed array.
    """
    result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True, check=True)
    return result.stdout

def compute_token_hash(token: str) -> str:
    """
    BENIGN: Pure Cryptographic Hashing Routine
    Standard string hashing with no external side-effects or input sinks.
    """
    salt = b"zerosentinel_static_salt"
    return hashlib.sha256(salt + token.encode("utf-8")).hexdigest()
