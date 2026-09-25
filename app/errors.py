class ScanAPIError(Exception):
    """Maps 1:1 to the error table in the spec (§2.4)."""

    http_status: int = 400
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, error_code: str | None = None, http_status: int | None = None):
        super().__init__(message)
        self.message = message
        if error_code:
            self.error_code = error_code
        if http_status:
            self.http_status = http_status


class MissingFileError(ScanAPIError):
    http_status = 400
    error_code = "MISSING_FILE"


class InvalidFileTypeError(ScanAPIError):
    http_status = 400
    error_code = "INVALID_FILE_TYPE"


class FileTooLargeError(ScanAPIError):
    http_status = 413
    error_code = "FILE_TOO_LARGE"


class CorruptOrUnreadableError(ScanAPIError):
    http_status = 422
    error_code = "CORRUPT_OR_UNREADABLE"


class SuspiciousArchiveError(ScanAPIError):
    """Zip-bomb-shaped .docx — decompression ratio or total size guard tripped."""
    http_status = 422
    error_code = "SUSPICIOUS_ARCHIVE"


class RateLimitedError(ScanAPIError):
    http_status = 429
    error_code = "RATE_LIMITED"


class EngineUnavailableError(ScanAPIError):
    http_status = 502
    error_code = "ENGINE_UNAVAILABLE"


class ScanTimeoutError(ScanAPIError):
    http_status = 504
    error_code = "SCAN_TIMEOUT"


class UnauthorizedError(ScanAPIError):
    http_status = 401
    error_code = "UNAUTHORIZED"
