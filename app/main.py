"""暫存檔案上傳與病毒掃描 API — reference implementation.

Data-never-lands-on-disk, end to end:

  1. The multipart body is parsed with Starlette's `max_part_size` set
     above our own file-size ceiling, so the per-part `SpooledTemporaryFile`
     never rolls over to a real file on disk (see README "How the
     in-memory guarantee actually works" for why this matters and why
     the naive `UploadFile = File(...)` dependency does NOT give you
     this guarantee out of the box).
  2. Content validation (validation.py) and hashing (scanner.py) operate
     on the resulting `bytes` object, in RAM only.
  3. The AV scan streams those same bytes to clamd over a socket via
     INSTREAM — clamd never receives a file path.
  4. Nothing is ever passed to `open(..., "wb")` or
     `tempfile.NamedTemporaryFile(delete=False)` anywhere in this codebase.
"""
import asyncio
import logging
import time
import uuid

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config import Settings, get_settings
from app.errors import MissingFileError, ScanAPIError, UnauthorizedError
from app.logging_conf import audit_log, configure_logging
from app.metrics import (
    scan_duration_seconds,
    scan_engine_unavailable_total,
    scan_requests_total,
    scan_threats_detected_total,
)
from app.rate_limit import FixedWindowRateLimiter
from app.scanner import engine_version_sync, ping_sync, scan_bytes
from app.schemas import HealthResponse, ScanErrorResponse, ScanSuccessResponse
from app.validation import detect_and_validate

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("scan_api")

app = FastAPI(title="暫存檔案上傳與病毒掃描 API", version="1.0.0")

_rate_limiter = FixedWindowRateLimiter(settings.rate_limit_per_minute)
_scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if not settings.api_token:
        return  # auth disabled — fine for local/dev, see README for production guidance
    expected = f"Bearer {settings.api_token}"
    if authorization != expected:
        raise UnauthorizedError("缺少或無效的 Authorization 標頭")


@app.exception_handler(ScanAPIError)
async def handle_scan_api_error(request: Request, exc: ScanAPIError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    if exc.error_code == "ENGINE_UNAVAILABLE":
        scan_engine_unavailable_total.inc()
    audit_log(
        logger, "scan_request_failed",
        request_id=request_id, error_code=exc.error_code, http_status=exc.http_status,
    )
    body = ScanErrorResponse(error_code=exc.error_code, message=exc.message, request_id=request_id)
    return JSONResponse(status_code=exc.http_status, content=body.model_dump())


@app.post("/api/v1/scan", response_model=ScanSuccessResponse)
async def scan_file(
    request: Request,
    _auth: None = Depends(require_auth),
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
) -> ScanSuccessResponse:
    request_id = x_request_id or str(uuid.uuid4())
    request.state.request_id = request_id
    client_ip = request.client.host if request.client else "unknown"

    _rate_limiter.check(client_ip)

    # Reject oversized uploads from the Content-Length header before
    # touching the body at all (spec §8 — DoS guard).
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_file_size_bytes:
        from app.errors import FileTooLargeError
        raise FileTooLargeError(f"檔案超過 {settings.max_file_size_mb}MB 限制")

    # max_part_size is set above our own ceiling so Starlette's per-part
    # SpooledTemporaryFile never rolls over to disk for an allowed-size file.
    form = await request.form(max_part_size=settings.max_file_size_bytes + 1)
    upload = form.get("file")
    if upload is None:
        raise MissingFileError("缺少檔案欄位")

    content = await upload.read()
    await upload.close()

    if len(content) > settings.max_file_size_bytes:
        from app.errors import FileTooLargeError
        raise FileTooLargeError(f"檔案超過 {settings.max_file_size_mb}MB 限制")

    filename = upload.filename or "unknown"
    detect_and_validate(filename, content, settings)

    if not ping_sync(settings):
        from app.errors import EngineUnavailableError
        raise EngineUnavailableError("掃描服務暫時無法使用")

    started = time.monotonic()
    async with _scan_semaphore:
        result = await scan_bytes(content, settings)
    scan_duration_seconds.observe(time.monotonic() - started)

    # `content` (and `form`/`upload`) go out of scope here; nothing keeps
    # the file bytes alive beyond this request.
    del content

    scan_requests_total.labels(result="safe" if result.is_safe else "threat").inc()
    if not result.is_safe:
        scan_threats_detected_total.labels(threat_name=result.threat_name or "unknown").inc()

    audit_log(
        logger, "scan_request_completed",
        request_id=request_id, source_ip=client_ip, filename=filename,
        sha256=result.sha256, file_type=filename.rsplit(".", 1)[-1],
        is_safe=result.is_safe, threat_name=result.threat_name,
        scan_engine_version=result.engine_version, duration_ms=result.duration_ms,
        http_status=200,
    )

    message = "掃描完成，未發現威脅" if result.is_safe else f"偵測到威脅：{result.threat_name}"
    return ScanSuccessResponse(
        is_safe=result.is_safe,
        message=message,
        filename=filename,
        sha256=result.sha256,
        scan_engine=result.engine_version,
        duration_ms=result.duration_ms,
        request_id=request_id,
    )


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    connected = ping_sync(settings)
    return HealthResponse(
        status="ok" if connected else "degraded",
        clamd="connected" if connected else "unreachable",
        scan_engine=engine_version_sync(settings) if connected else None,
    )


@app.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
