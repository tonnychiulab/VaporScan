# 規格書：暫存檔案上傳與病毒掃描 API

版本：v1.0　日期：2026-09-25　作者：Tonny

## 1. 概述 (Overview)
建立一個輕量級的 HTTP POST API，允許外部系統上傳檔案進行病毒掃描，並回傳掃描結果。

**核心安全約束**：必須嚴格符合「資料不落地」原則，所有檔案串流與掃描過程均需在記憶體（Memory）內完成，嚴禁將任何上傳檔案寫入伺服器的本機硬碟。

## 2. API 介面合約 (Interface Contract)

### 2.1 端點
`POST /api/v1/scan`

### 2.2 輸入
- Content-Type：`multipart/form-data`
- 欄位：`file`（必填，僅限 `.pdf`, `.docx`）
- 檔案大小上限：**25 MB**（可透過環境變數 `MAX_FILE_SIZE_MB` 調整）
- 建議標頭：`X-Request-Id`（選填，若未提供由伺服器產生，用於稽核追蹤）

### 2.3 成功輸出（HTTP 200）
```json
{
  "status": "success",
  "is_safe": true,
  "message": "掃描完成，未發現威脅",
  "filename": "report.pdf",
  "sha256": "3b1e...c9",
  "scan_engine": "ClamAV 1.4.1 / sig-db 2026-09-25",
  "duration_ms": 842,
  "request_id": "req-9f2a3c"
}
```

當掃描發現威脅時（仍為 HTTP 200，因為「掃描成功執行」與「檔案是否安全」是兩件事）：
```json
{
  "status": "success",
  "is_safe": false,
  "message": "偵測到威脅：Win.Trojan.Generic-12345",
  "filename": "invoice.docx",
  "sha256": "8a4f...12",
  "scan_engine": "ClamAV 1.4.1 / sig-db 2026-09-25",
  "duration_ms": 611,
  "request_id": "req-9f2a3d"
}
```

### 2.4 失敗輸出（錯誤情境）

| HTTP 狀態碼 | error code | 情境 | message 範例 |
|---|---|---|---|
| 400 | `MISSING_FILE` | 未提供 `file` 欄位 | "缺少檔案欄位" |
| 400 | `INVALID_FILE_TYPE` | 副檔名或 MIME 不符 `.pdf`/`.docx` | "不支援的檔案格式" |
| 413 | `FILE_TOO_LARGE` | 超過大小上限 | "檔案超過 25MB 限制" |
| 422 | `CORRUPT_OR_UNREADABLE` | 檔案無法解析（損毀） | "檔案內容無法讀取" |
| 422 | `SUSPICIOUS_ARCHIVE` | DOCX 疑似 Zip Bomb（實作新增，見 §8） | "解壓縮比超過上限，疑似 Zip Bomb" |
| 429 | `RATE_LIMITED` | 超過速率限制 | "請求過於頻繁，請稍後再試" |
| 502 | `ENGINE_UNAVAILABLE` | 掃描引擎（clamd）無法連線 | "掃描服務暫時無法使用" |
| 504 | `SCAN_TIMEOUT` | 掃描逾時 | "掃描逾時" |
| 401 | `UNAUTHORIZED` | 缺少/無效的 Authorization 標頭（若啟用 `API_TOKEN`） | "缺少或無效的 Authorization 標頭" |
| 500 | `INTERNAL_ERROR` | 未預期例外 | "系統內部錯誤" |

失敗回應統一格式：
```json
{
  "status": "error",
  "error_code": "FILE_TOO_LARGE",
  "message": "檔案超過 25MB 限制",
  "request_id": "req-9f2a3e"
}
```

## 3. 檔案類型驗證 (Content Validation)
- **雙重驗證**：不可僅信任副檔名，需以 Magic Number 驗證實際檔案內容是否為 PDF（`%PDF-`）或 DOCX（ZIP `PK\x03\x04` 且內含 `[Content_Types].xml`）。
- 副檔名與實際內容不符 → 回傳 `INVALID_FILE_TYPE`，並記錄為潛在偽裝攻擊事件。

## 4. 記憶體內處理原則 (In-Memory Only, 資料不落地)
- 上傳串流須以記憶體緩衝區接收，全程不得呼叫任何檔案系統寫入 API。**注意**：Web 框架自身的 multipart 解析器可能有預設的暫存門檻（例如 Starlette 的 `SpooledTemporaryFile` 預設 1MB），必須明確設定高於允許的檔案大小上限，才能確保真正不落地（詳見 README「為什麼資料不落地比想像中難做到」一節）。
- 若使用 ClamAV，採用 `clamd` 的 **INSTREAM** 協定，透過 TCP/Unix Socket 將位元組流分段（chunk）直接送入 clamd 常駐程序掃描，不落地至暫存磁碟。
- 掃描完成（無論成功或失敗）後，緩衝區物件應立即釋放，不保留檔案內容於記憶體超過請求生命週期。
- `sha256` 須在記憶體中計算，不得為此另存一份檔案。
- 伺服器日誌嚴禁記錄檔案原始內容，僅可記錄檔名、雜湊值、掃描結果與 metadata。

## 5. 掃描引擎整合 (Scan Engine Integration)
- 建議：ClamAV `clamd` daemon，透過 Python `clamd` 套件呼叫 `instream()`。
- Timeout 設定：單檔掃描逾時預設 **15 秒**（可調），逾時回傳 `SCAN_TIMEOUT` 並中斷串流。
- 健康檢查：API 啟動時應 ping clamd（`PING` → `PONG`），若無法連線，`/healthz` 回報 unhealthy。
- 病毒碼更新：建議 `freshclam` 每小時自動更新，API 回應中的 `scan_engine` 欄位應反映當前病毒碼版本，供稽核追溯。

## 6. 併發與速率限制 (Concurrency & Rate Limiting)
- 每 IP 或每 API Key 建議限制：**10 requests/min**（依部署情境調整）。
- 全域併發掃描數上限：建議 `min(CPU核心數 * 2, 20)`，超過則回傳 429，避免記憶體暴增。

## 7. 稽核與日誌 (Audit Logging)
每次請求須記錄下列欄位（送入 SIEM，例如 Graylog）：

| 欄位 | 說明 |
|---|---|
| `request_id` | 唯一請求識別碼 |
| `timestamp` | ISO 8601 時間戳 |
| `source_ip` | 呼叫端來源 IP |
| `filename` | 原始檔名（僅記錄名稱，非內容） |
| `sha256` | 檔案雜湊 |
| `file_type` | 驗證後之實際類型 |
| `is_safe` | 掃描結果 |
| `threat_name` | 若偵測到威脅，記錄病毒名稱 |
| `scan_engine_version` | 病毒碼版本 |
| `duration_ms` | 掃描耗時 |
| `http_status` | 回應狀態碼 |

日誌不得包含檔案內容或個資明文。

## 8. 安全考量補充 (Additional Security Considerations)
- **Zip Bomb / 解壓炸彈防護**：DOCX 本質為 ZIP，需限制解壓縮後大小比例（例如壓縮比超過 100:1 即中止並判定為可疑，回傳 `SUSPICIOUS_ARCHIVE`）。
- **檔名注入防護**：回應中的 `filename` 應做 HTML/JSON escape，避免反射型攻擊。
- **API 驗證**：建議要求 `Authorization: Bearer <token>` 或 mTLS。
- **DoS 防護**：對超大檔案應在讀取 Header（`Content-Length`）階段即拒絕。
- **威脅發現後續動作**：若 `is_safe: false`，僅回傳結果、不轉存/不隔離檔案，由呼叫端自行處置。

## 9. 非功能性需求 (Non-Functional Requirements)
- 可用性目標：99.5%
- 單一請求最大處理時間：20 秒（含逾時緩衝）
- 水平擴展：API 層可無狀態擴展，clamd 可獨立部署為共用服務或 sidecar

## 10. 健康檢查與監控端點
- `GET /healthz`：回傳 API 與 clamd 連線狀態
- `GET /metrics`：Prometheus 格式

---

### 版本紀錄
| 版本 | 日期 | 說明 |
|---|---|---|
| v0.1 | 2026-09-25 | 初稿：定義概要與 API 介面合約 |
| v1.0 | 2026-09-25 | 補完失敗輸出、驗證、記憶體處理、掃描引擎整合、稽核、安全考量等章節 |
