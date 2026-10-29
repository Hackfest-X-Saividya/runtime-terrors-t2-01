from typing import Any, Optional


class ZeroSentinelException(Exception):
    """Base exception for ZeroSentinel backend."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None, status_code: int = 400):
        self.code = code
        self.message = message
        self.details = details
        self.status_code = status_code
        super().__init__(message)


class IngestionError(ZeroSentinelException):
    """Raised when ingestion validation or extraction fails."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None):
        super().__init__(code=code, message=message, details=details, status_code=400)


class SecurityViolationError(ZeroSentinelException):
    """Raised when a security guardrail (SSRF, path traversal) is tripped."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None):
        super().__init__(code=code, message=message, details=details, status_code=400)


class AnalyzerError(ZeroSentinelException):
    """Raised when a static analyzer fails unexpectedly."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None):
        super().__init__(code=code, message=message, details=details, status_code=500)
