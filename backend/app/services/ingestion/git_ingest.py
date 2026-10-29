import ipaddress
import logging
import os
import re
import socket
import subprocess
import urllib.parse
from typing import Set

from app.core.config import settings
from app.core.exceptions import IngestionError, SecurityViolationError

logger = logging.getLogger("zerosentinel.git_ingest")

ALLOWED_GIT_DOMAINS: Set[str] = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
}

DISALLOWED_HOSTS: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
}


def validate_git_url(git_url: str) -> urllib.parse.SplitResult:
    """
    Validates the Git repository URL against strict domain allowlists and SSRF protections.

    Security Limitation (TOCTOU / DNS Rebinding):
    Pre-resolving DNS in Python confirms that hostnames resolve to global IPs at validation
    time, significantly mitigating accidental internal scanning. However, because 'git clone'
    performs its own independent DNS resolution during execution, userland pre-resolution does
    not guarantee complete immunity to DNS rebinding attacks. In production, kernel-level or
    proxy-level egress controls are required.
    """
    if not git_url or not git_url.strip():
        raise IngestionError("EMPTY_GIT_URL", "Git URL must not be empty.")

    # Reject shell control characters
    if re.search(r"[;&|$\`\n\r]", git_url):
        raise SecurityViolationError("INVALID_GIT_URL", "Git URL contains illegal control characters.")

    try:
        parsed = urllib.parse.urlsplit(git_url.strip())
    except Exception as exc:
        raise IngestionError("INVALID_GIT_URL", f"Malformed Git URL: {exc}")

    # 1. Scheme must be strictly HTTPS
    if parsed.scheme.lower() != "https":
        raise SecurityViolationError(
            "UNSUPPORTED_PROTOCOL",
            f"Only HTTPS protocol is permitted for Git URLs (received '{parsed.scheme}').",
        )

    # 2. Reject embedded credentials
    if parsed.username or parsed.password:
        raise SecurityViolationError(
            "CREDENTIALS_DISALLOWED",
            "Embedded user credentials in Git URLs are strictly prohibited.",
        )

    # 3. Port must be 443 or default
    if parsed.port not in (None, 443):
        raise SecurityViolationError(
            "INVALID_PORT",
            f"Non-standard port '{parsed.port}' is prohibited; only default HTTPS port 443 is allowed.",
        )

    # 4. Hostname validation against explicit allowlist
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise IngestionError("INVALID_GIT_URL", "Git URL is missing a valid hostname.")

    if hostname in DISALLOWED_HOSTS or hostname not in ALLOWED_GIT_DOMAINS:
        raise SecurityViolationError(
            "DISALLOWED_DOMAIN",
            f"Domain '{hostname}' is not in the approved Git hosting allowlist ({sorted(ALLOWED_GIT_DOMAINS)}).",
        )

    # 5. Pre-clone DNS resolution and IP address validation
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise IngestionError("DNS_RESOLUTION_FAILED", f"Failed to resolve Git host '{hostname}': {exc}")

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SecurityViolationError("INVALID_IP_ADDRESS", f"Invalid IP returned: {ip_str}")

        if not ip.is_global:
            raise SecurityViolationError(
                "SSRF_DETECTED",
                f"Resolved IP '{ip_str}' for host '{hostname}' is non-global or private.",
            )

    return parsed


def validate_git_branch(branch: str) -> str:
    """
    Validates branch name using Git's native 'git check-ref-format --branch' parser.
    Rejects option injection attempts (leading dashes).
    """
    if not branch or not branch.strip():
        return "main"

    clean_branch = branch.strip()

    # Prevent option injection
    if clean_branch.startswith("-"):
        raise SecurityViolationError(
            "INVALID_BRANCH_NAME",
            f"Branch names starting with '-' are prohibited to prevent option injection: '{clean_branch}'",
        )

    # Invoke Git native ref validator with shell=False
    try:
        proc = subprocess.run(
            ["git", "check-ref-format", "--branch", clean_branch],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            raise SecurityViolationError(
                "INVALID_BRANCH_NAME",
                f"Branch name '{clean_branch}' is not a valid Git reference: {proc.stderr.strip()}",
            )
    except subprocess.TimeoutExpired:
        raise IngestionError("BRANCH_VALIDATION_TIMEOUT", "Branch validation timed out.")
    except FileNotFoundError:
        # If git binary is not installed, fallback to safe regex
        if not re.match(r"^[a-zA-Z0-9._/-]+$", clean_branch) or ".." in clean_branch:
            raise SecurityViolationError("INVALID_BRANCH_NAME", f"Invalid branch reference: '{clean_branch}'")

    return clean_branch


def clone_git_repository(git_url: str, branch: str, target_dir: str) -> None:
    """
    Clones a Git repository using safe subprocess arguments, strict shallow depth,
    and timeout bounds.
    """
    validate_git_url(git_url)
    validated_branch = validate_git_branch(branch)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--branch",
        validated_branch,
        "--",
        git_url,
        target_dir,
    ]

    try:
        subprocess.run(
            cmd,
            shell=False,
            timeout=settings.GIT_CLONE_TIMEOUT_SECONDS,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        raise IngestionError(
            "INGESTION_TIMEOUT",
            f"Git clone exceeded timeout of {settings.GIT_CLONE_TIMEOUT_SECONDS} seconds.",
        )
    except subprocess.CalledProcessError as exc:
        raise IngestionError(
            "GIT_CLONE_FAILED",
            f"Git clone failed: {exc.stderr.strip() or exc.stdout.strip()}",
        )
    except FileNotFoundError:
        raise IngestionError("GIT_NOT_FOUND", "The 'git' binary is not installed on the system.")

    # Post-clone directory size check
    total_size = 0
    for dirpath, _, filenames in os.walk(target_dir):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)

    if total_size > settings.MAX_REPO_SIZE_BYTES:
        raise IngestionError(
            "REPO_SIZE_EXCEEDED",
            f"Cloned repository footprint ({total_size} bytes) exceeds limit of {settings.MAX_REPO_SIZE_BYTES} bytes.",
        )
