"""Minimal in-process rate limiting.

This is a fixed-window counter per client IP, good enough for a single
worker process. If you scale this API horizontally, swap this for a
shared store (Redis `INCR` + `EXPIRE`) so limits are enforced across
instances — see README "Production notes".
"""
import time
from collections import defaultdict

from app.errors import RateLimitedError


class FixedWindowRateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self._windows: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))

    def check(self, client_key: str) -> None:
        window = int(time.time() // 60)
        window_start, count = self._windows[client_key]
        if window_start != window:
            window_start, count = window, 0
        count += 1
        self._windows[client_key] = (window_start, count)
        if count > self.limit_per_minute:
            raise RateLimitedError("請求過於頻繁，請稍後再試")
