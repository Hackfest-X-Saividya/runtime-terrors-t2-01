import subprocess
import pytest

from app.core.exceptions import IngestionError, SecurityViolationError
from app.services.ingestion.git_ingest import (
    clone_git_repository,
    validate_git_branch,
    validate_git_url,
)


def test_git_url_valid(monkeypatch):
    """Verify valid HTTPS allowlisted Git URLs succeed."""
    # Mock socket.getaddrinfo to return a globally routable public IP (e.g. 140.82.112.4)
    import socket
    def mock_getaddrinfo(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.4", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    parsed = validate_git_url("https://github.com/example-org/sample-repo.git")
    assert parsed.hostname == "github.com"
    assert parsed.scheme == "https"


def test_git_url_disallowed_domain(monkeypatch):
    """Verify rejection of domains not in the explicit allowlist."""
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("https://malicious-site.com/repo.git")
    assert exc_info.value.code == "DISALLOWED_DOMAIN"


def test_git_url_non_https():
    """Verify rejection of non-HTTPS protocols (http, ssh, git, file)."""
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("http://github.com/repo.git")
    assert exc_info.value.code == "UNSUPPORTED_PROTOCOL"

    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("file:///etc/passwd")
    assert exc_info.value.code == "UNSUPPORTED_PROTOCOL"


def test_git_url_credentials_prohibited():
    """Verify rejection of URLs with embedded credentials."""
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("https://user:password@github.com/repo.git")
    assert exc_info.value.code == "CREDENTIALS_DISALLOWED"


def test_git_url_non_standard_port():
    """Verify rejection of non-443 ports."""
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("https://github.com:8443/repo.git")
    assert exc_info.value.code == "INVALID_PORT"


def test_git_url_ssrf_private_ip(monkeypatch):
    """Verify rejection when hostname resolves to a private or loopback IP."""
    import socket
    def mock_getaddrinfo_private(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_private)

    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_url("https://github.com/repo.git")
    assert exc_info.value.code == "SSRF_DETECTED"


def test_git_branch_validation():
    """Verify branch validation accepts standard names and rejects leading dashes."""
    # Valid branch references
    assert validate_git_branch("main") == "main"
    assert validate_git_branch("feature/security-patch") == "feature/security-patch"
    assert validate_git_branch("v1.0.0") == "v1.0.0"

    # Option injection attempts (leading dashes)
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_branch("--upload-pack=touch /tmp/pwn")
    assert exc_info.value.code == "INVALID_BRANCH_NAME"

    with pytest.raises(SecurityViolationError) as exc_info:
        validate_git_branch("-u")
    assert exc_info.value.code == "INVALID_BRANCH_NAME"


def test_clone_git_repository_argument_safety(monkeypatch):
    """Verify clone_git_repository constructs safe subprocess argument list with shell=False and '--'."""
    captured_args = {}

    def mock_subprocess_run(cmd, **kwargs):
        captured_args["cmd"] = cmd
        captured_args["kwargs"] = kwargs
        # Simulate successful clone
        class MockProc:
            returncode = 0
            stdout = ""
            stderr = ""
        return MockProc()

    # Mock validate_git_url and subprocess.run
    monkeypatch.setattr("app.services.ingestion.git_ingest.validate_git_url", lambda url: None)
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    clone_git_repository("https://github.com/org/repo.git", "main", "/fake/target/dir")

    cmd = captured_args["cmd"]
    kwargs = captured_args["kwargs"]

    assert kwargs["shell"] is False
    assert cmd[0] == "git"
    assert cmd[1] == "clone"
    assert "--depth" in cmd
    assert "--branch" in cmd
    assert "--" in cmd
    # Ensure '--' precedes the URL
    dash_index = cmd.index("--")
    assert cmd[dash_index + 1] == "https://github.com/org/repo.git"
