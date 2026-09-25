# VaporScan

**A temp-file-upload virus-scanning API — files scan and vanish like vapor, never touching disk.**

[正體中文說明](./README.zh-TW.md)

## What this is

A lightweight HTTP API that lets external systems upload `.pdf` / `.docx` files for antivirus scanning and get back a structured result.

**The core design constraint (and the project's namesake): data never lands on disk.** From the moment an upload enters the process to the moment the scan completes, the file exists only in memory — never written to the server's local disk in any form, including the web framework's own multipart temp-file mechanism.

Full spec: [`docs/spec.md`](./docs/spec.md).

## Why "never touches disk" is harder than it looks

If you've written a file-upload endpoint in FastAPI/Starlette before, the default move is:

```python
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
```

**This does not actually guarantee your file stays in memory.** Starlette's multipart parser backs every file field with a `tempfile.SpooledTemporaryFile(max_size=1MB)` by default — anything over 1MB really does get written to the system temp directory, which is exactly the behavior this project exists to prevent.

This project's fix (see `app/main.py`) is to call:

```python
form = await request.form(max_part_size=settings.max_file_size_bytes + 1)
```

This sets Starlette's spool threshold above our own allowed file-size ceiling, so `SpooledTemporaryFile` never rolls over to disk for any file within the accepted size. It's the easiest detail to miss, and it's the actual security property the whole spec is built around.

The rest of the data path:

1. Content validation (`app/validation.py`) and hashing (`app/scanner.py`) operate on the resulting in-memory `bytes` object.
2. The scan engine talks to ClamAV's `clamd` daemon over its **INSTREAM** protocol, streaming those same bytes directly — `clamd` never receives a file path either.
3. There is not a single call to `open(..., "wb")` or `tempfile.NamedTemporaryFile(delete=False)` anywhere in this codebase.

## Quick start

### Docker Compose (recommended, includes ClamAV)

```bash
cp .env.example .env
docker compose up --build
```

On first boot, the ClamAV container downloads its signature databases, which can take a few minutes — watch progress with `docker compose logs -f clamav`.

### Local development (bring your own clamd)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # point at your local clamd
uvicorn app.main:app --reload
```

### Tests

```bash
pytest
```

Tests mock out clamd, so you don't need ClamAV installed locally to run them.

## API example

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@report.pdf"
```

Success response:

```json
{
  "status": "success",
  "is_safe": true,
  "message": "掃描完成，未發現威脅",
  "filename": "report.pdf",
  "sha256": "3b1e...c9",
  "scan_engine": "ClamAV 1.4.1/27431/...",
  "duration_ms": 842,
  "request_id": "..."
}
```

Full error-code table and response shapes are in [`docs/spec.md`](./docs/spec.md) §2.4.

## Environment variables

See [`.env.example`](./.env.example) — everything has a sane default. Highlights:

| Variable | What it does |
|---|---|
| `API_TOKEN` | If set, every request must send `Authorization: Bearer <token>` |
| `MAX_FILE_SIZE_MB` | Upload size ceiling (default 25) |
| `CLAMD_HOST` / `CLAMD_PORT` / `CLAMD_UNIX_SOCKET` | How to reach clamd; the Unix socket takes priority over TCP if set |
| `SCAN_TIMEOUT_SECONDS` | Per-file scan timeout (default 15s) |
| `MAX_CONCURRENT_SCANS` | Global concurrency cap, to bound memory usage under load |
| `RATE_LIMIT_PER_MINUTE` | Per-IP request limit |
| `ZIP_MAX_DECOMPRESSION_RATIO` / `ZIP_MAX_UNCOMPRESSED_TOTAL_MB` | Zip-bomb guard thresholds for `.docx` (which is a zip container) |

## Monitoring endpoints

- `GET /healthz` — reports clamd connectivity and the current signature-DB version
- `GET /metrics` — Prometheus format: `scan_requests_total`, `scan_threats_detected_total`, `scan_duration_seconds`, `scan_engine_unavailable_total`

## Audit logging

Every request emits a structured JSON line to stdout (tail it with Fluent Bit / Filebeat into Graylog or another SIEM), matching the field table in spec §7. It **never logs raw file content** — only filename, hash, scan result, and metadata.

## Production notes

- **Rate limiting** is currently a single-process fixed-window counter (`app/rate_limit.py`). If you scale to multiple instances, swap it for a shared store (Redis `INCR`/`EXPIRE`) — otherwise each instance counts independently and the limit stops meaning anything.
- **Auth** here is a minimal Bearer-token check. For production, put this behind mTLS or your existing API gateway / IdP.
- **Signature updates**: make sure `freshclam` runs on a schedule (the official ClamAV Docker image does this by default), or the `scan_engine` version in responses will go stale.

## License

MIT — see [`LICENSE`](./LICENSE).
