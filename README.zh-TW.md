# VaporScan

[![CI](https://github.com/tonnychiulab/VaporScan/actions/workflows/ci.yml/badge.svg)](https://github.com/tonnychiulab/VaporScan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/github/license/tonnychiulab/VaporScan)](./LICENSE)

**暫存檔案上傳與病毒掃描 API** — 檔案像蒸氣一樣，掃完即散，從不落地。

[English README](./README.md)

## 這是什麼

一個輕量級的 HTTP API，讓外部系統上傳 `.pdf` / `.docx` 檔案進行病毒掃描，並回傳結構化的掃描結果。

**核心設計約束（也是專案名稱的由來）：全程「資料不落地」。** 上傳的檔案從進入行程到掃描結束，只存在於記憶體中，從未以任何形式寫入伺服器本機硬碟——包含 Web 框架自己的 multipart 暫存機制。

完整規格請見 [`docs/spec.md`](./docs/spec.md)。

## 為什麼「資料不落地」比想像中難做到

如果你用 FastAPI／Starlette 寫過檔案上傳，你可能預設用：

```python
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
```

**這樣寫並不保證資料不落地。** Starlette 的 multipart 解析器預設會把每個檔案欄位寫進
`tempfile.SpooledTemporaryFile(max_size=1MB)`——超過 1MB 的檔案就會**真的落地**到系統暫存目錄，而這正是本專案要杜絕的行為。

本專案的解法（見 `app/main.py`）：明確呼叫

```python
form = await request.form(max_part_size=settings.max_file_size_bytes + 1)
```

把 Starlette 的 spool 門檻設定在我們自己允許的檔案大小上限之上，讓 `SpooledTemporaryFile` 對任何合法大小的檔案永遠停留在記憶體中，不觸發 rollover 到磁碟。這是本專案裡最容易被忽略、卻也是整份規格書真正的安全前提。

其餘的資料流：

1. 驗證（`app/validation.py`）與雜湊（`app/scanner.py`）都直接操作記憶體中的 `bytes`。
2. 掃描引擎串接 ClamAV 的 `clamd`，透過 **INSTREAM** 協定把 bytes 直接串流進 clamd 常駐程序——clamd 端也從未收到檔案路徑。
3. 整個程式碼庫搜尋不到任何一次 `open(..., "wb")` 或 `tempfile.NamedTemporaryFile(delete=False)` 呼叫。

## 快速開始

### 使用 Docker Compose（推薦，含 ClamAV）

```bash
cp .env.example .env
docker compose up --build
```

第一次啟動 ClamAV 容器會下載病毒碼資料庫，可能需要數分鐘，`docker compose logs -f clamav` 可觀察進度。

### 本機開發（需自行啟動 clamd）

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # 依你本機的 clamd 位置調整
uvicorn app.main:app --reload
```

### 測試

```bash
pytest
```

測試以 mock 取代真正的 clamd，因此不需要本機安裝 ClamAV 也能跑。

## API 範例

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@report.pdf"
```

成功回應：

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

完整的錯誤碼表與所有回應格式，請參閱 [`docs/spec.md`](./docs/spec.md) 第 2.4 節。

## 環境變數

見 [`.env.example`](./.env.example)，所有設定都有合理預設值，重點如下：

| 變數 | 說明 |
|---|---|
| `API_TOKEN` | 設定後所有請求需帶 `Authorization: Bearer <token>` |
| `MAX_FILE_SIZE_MB` | 上傳大小上限（預設 25） |
| `CLAMD_HOST` / `CLAMD_PORT` / `CLAMD_UNIX_SOCKET` | clamd 連線方式，設定 Unix socket 會優先於 TCP |
| `SCAN_TIMEOUT_SECONDS` | 單檔掃描逾時（預設 15 秒） |
| `MAX_CONCURRENT_SCANS` | 全域併發掃描數上限，避免記憶體暴增 |
| `RATE_LIMIT_PER_MINUTE` | 每 IP 每分鐘請求數限制 |
| `ZIP_MAX_DECOMPRESSION_RATIO` / `ZIP_MAX_UNCOMPRESSED_TOTAL_MB` | DOCX（本質為 ZIP）的解壓縮炸彈防護門檻 |

## 監控端點

- `GET /healthz` — 回報 clamd 連線狀態與目前病毒碼版本
- `GET /metrics` — Prometheus 格式，含 `scan_requests_total`、`scan_threats_detected_total`、`scan_duration_seconds`、`scan_engine_unavailable_total`

## 稽核日誌

所有請求以結構化 JSON 單行輸出到 stdout（供 Fluent Bit / Filebeat 送入 Graylog 或其他 SIEM），欄位對應規格書第 7 節，**絕不記錄檔案原始內容**，僅記錄檔名、雜湊值、掃描結果與中繼資料。

## 生產環境注意事項

- **速率限制**：目前為單一行程內的 fixed-window 計數器（`app/rate_limit.py`）。若水平擴展成多個實例，請改用 Redis `INCR`/`EXPIRE` 等共用儲存，否則各實例各算各的，限制形同虛設。
- **身分驗證**：範例僅提供簡單的 Bearer Token 比對；正式環境建議改用 mTLS 或接上既有的 API Gateway/IdP。
- **病毒碼更新**：確保 `freshclam` 定期執行（Docker 官方映像檔預設會跑），否則 `scan_engine` 回應中的版本會逐漸過期。

## 授權

MIT，見 [`LICENSE`](./LICENSE)。
