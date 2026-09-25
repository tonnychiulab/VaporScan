"""Basic tests. clamd is mocked so these run without a real daemon.

Run with: pytest
"""
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.scanner import ScanResult

client = TestClient(app)

MINIMAL_PDF = b"%PDF-1.4\n%%EOF"


def test_missing_file_returns_400():
    resp = client.post("/api/v1/scan")
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "MISSING_FILE"


def test_wrong_extension_returns_400():
    resp = client.post(
        "/api/v1/scan",
        files={"file": ("malware.exe", b"MZ...", "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "INVALID_FILE_TYPE"


def test_extension_mismatch_returns_400():
    # Real PDF bytes, but claiming a .docx extension.
    resp = client.post(
        "/api/v1/scan",
        files={"file": ("fake.docx", MINIMAL_PDF, "application/pdf")},
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "INVALID_FILE_TYPE"


@patch("app.main.ping_sync", return_value=True)
@patch("app.main.scan_bytes", new_callable=AsyncMock)
def test_clean_pdf_returns_safe(mock_scan_bytes, _mock_ping):
    mock_scan_bytes.return_value = ScanResult(
        is_safe=True,
        threat_name=None,
        engine_version="ClamAV 1.4.1/test",
        sha256="deadbeef",
        duration_ms=12,
    )
    resp = client.post(
        "/api/v1/scan",
        files={"file": ("report.pdf", MINIMAL_PDF, "application/pdf")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["is_safe"] is True
    assert body["sha256"] == "deadbeef"


@patch("app.main.ping_sync", return_value=False)
def test_engine_unavailable_returns_502(_mock_ping):
    resp = client.post(
        "/api/v1/scan",
        files={"file": ("report.pdf", MINIMAL_PDF, "application/pdf")},
    )
    assert resp.status_code == 502
    assert resp.json()["error_code"] == "ENGINE_UNAVAILABLE"


def test_healthz_reports_disconnected_without_clamd():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] in {"ok", "degraded"}
