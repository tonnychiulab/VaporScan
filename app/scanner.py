"""ClamAV integration via clamd's INSTREAM protocol.

INSTREAM sends the file to the clamd daemon over a socket in chunks;
clamd never receives a file path and never touches its own disk for
the scan target either. Nothing here calls open(..., "wb") or
tempfile.NamedTemporaryFile(delete=False) — search the codebase for
those two calls and you should find zero hits outside this comment.
"""
import asyncio
import hashlib
import io
import time
from dataclasses import dataclass
from functools import lru_cache

import clamd

from app.config import Settings
from app.errors import EngineUnavailableError, ScanTimeoutError


@dataclass(frozen=True)
class ScanResult:
    is_safe: bool
    threat_name: str | None
    engine_version: str
    sha256: str
    duration_ms: int


def _build_client(settings: Settings):
    if settings.clamd_unix_socket:
        return clamd.ClamdUnixSocket(path=settings.clamd_unix_socket, timeout=settings.scan_timeout_seconds)
    return clamd.ClamdNetworkSocket(
        host=settings.clamd_host, port=settings.clamd_port, timeout=settings.scan_timeout_seconds
    )


@lru_cache
def get_client(settings: Settings):
    return _build_client(settings)


def ping_sync(settings: Settings) -> bool:
    try:
        return get_client(settings).ping() == "PONG"
    except (clamd.ConnectionError, OSError):
        return False


def engine_version_sync(settings: Settings) -> str:
    try:
        # clamd.version() returns e.g. "ClamAV 1.4.1/27431/Wed Sep 24 08:12:00 2026"
        return get_client(settings).version()
    except (clamd.ConnectionError, OSError):
        return "unknown"


def _instream_sync(content: bytes, settings: Settings) -> dict:
    client = get_client(settings)
    try:
        result = client.instream(io.BytesIO(content))
    except clamd.ConnectionError as exc:
        raise EngineUnavailableError("掃描服務暫時無法使用") from exc
    return result


async def scan_bytes(content: bytes, settings: Settings) -> ScanResult:
    """Streams `content` (already fully in memory) to clamd and hashes it
    concurrently. Raises EngineUnavailableError / ScanTimeoutError.
    """
    started = time.monotonic()
    sha256 = hashlib.sha256(content).hexdigest()

    loop = asyncio.get_running_loop()
    try:
        raw_result = await asyncio.wait_for(
            loop.run_in_executor(None, _instream_sync, content, settings),
            timeout=settings.scan_timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise ScanTimeoutError("掃描逾時") from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    engine_version = await loop.run_in_executor(None, engine_version_sync, settings)

    # clamd's instream() returns {'stream': ('OK', None)} or
    # {'stream': ('FOUND', 'Win.Trojan.Generic-12345')}
    status, threat_name = raw_result.get("stream", ("ERROR", None))
    is_safe = status == "OK"

    return ScanResult(
        is_safe=is_safe,
        threat_name=threat_name if not is_safe else None,
        engine_version=engine_version,
        sha256=sha256,
        duration_ms=duration_ms,
    )
