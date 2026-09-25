from typing import Literal
from pydantic import BaseModel


class ScanSuccessResponse(BaseModel):
    status: Literal["success"] = "success"
    is_safe: bool
    message: str
    filename: str
    sha256: str
    scan_engine: str
    duration_ms: int
    request_id: str


class ScanErrorResponse(BaseModel):
    status: Literal["error"] = "error"
    error_code: str
    message: str
    request_id: str


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    clamd: Literal["connected", "unreachable"]
    scan_engine: str | None = None
