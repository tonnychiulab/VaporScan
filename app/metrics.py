from prometheus_client import Counter, Histogram

scan_requests_total = Counter(
    "scan_requests_total", "Total scan requests received", ["result"]
)
scan_threats_detected_total = Counter(
    "scan_threats_detected_total", "Total threats detected", ["threat_name"]
)
scan_duration_seconds = Histogram(
    "scan_duration_seconds", "Time spent scanning a file, in seconds"
)
scan_engine_unavailable_total = Counter(
    "scan_engine_unavailable_total", "Count of times clamd was unreachable"
)
