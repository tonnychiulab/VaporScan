"""Centralized configuration, loaded entirely from environment variables.

Nothing here ever touches disk for file data — this module only holds
tunables (sizes, timeouts, hosts). See README for the full list.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", frozen=True)

    # --- API behavior ---
    api_token: str | None = None  # if set, Authorization: Bearer <token> is required
    max_file_size_mb: int = 25
    allowed_extensions: tuple[str, ...] = (".pdf", ".docx")

    # --- ClamAV (clamd) ---
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_unix_socket: str | None = None  # e.g. /var/run/clamav/clamd.ctl (takes priority if set)
    scan_timeout_seconds: int = 15

    # --- Concurrency & rate limiting ---
    max_concurrent_scans: int = 20
    rate_limit_per_minute: int = 10

    # --- Zip bomb guard (applies to .docx, which is a zip container) ---
    zip_max_decompression_ratio: int = 100
    zip_max_uncompressed_total_mb: int = 200

    # --- Logging ---
    log_level: str = "INFO"

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
