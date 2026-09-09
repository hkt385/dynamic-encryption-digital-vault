import logging

logger = logging.getLogger("vault")


class VaultError(Exception):
    """Contains only a stable, non-sensitive code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


HTTP_STATUS = {
    "AUTH_REQUIRED": 401,
    "AUTH_INVALID": 401,
    "ACCESS_DENIED": 403,
    "INVALID_REQUEST": 400,
    "FILE_TOO_LARGE": 413,
    "QUOTA_EXCEEDED": 409,
    "RATE_LIMITED": 429,
    "BUSY": 503,
    "KEY_UNAVAILABLE": 503,
    "DATABASE_UNAVAILABLE": 503,
    "UPLOAD_FAILED": 503,
    "DECRYPTION_FAILED": 500,
    "INTERNAL_ERROR": 500,
}


def safe_event(code: str, request_id) -> None:
    # Never pass exception messages, request objects, headers, or locals.
    logger.warning("code=%s request_id=%s", code, request_id)
