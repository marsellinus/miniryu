import logging
import threading
import time
from collections import deque


class SecurityEventLogger:
    """Thread-safe logger that keeps recent in-memory events for dashboards."""

    def __init__(self, name="sdn-security", max_events=500):
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)
        self._events = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def log_event(
        self,
        event_type,
        message,
        severity="info",
        details=None,
    ):
        details = details or {}
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details,
        }
        with self._lock:
            self._events.append(event)

        level = severity.lower()
        if level in ("warn", "warning"):
            self._logger.warning("[%s] %s | %s", event_type, message, details)
        elif level == "error":
            self._logger.error("[%s] %s | %s", event_type, message, details)
        else:
            self._logger.info("[%s] %s | %s", event_type, message, details)

    def get_recent_events(self, limit=100):
        with self._lock:
            return list(self._events)[-limit:]

    def get_recent_attacks(self, limit=100):
        attacks = []
        for event in self.get_recent_events(limit=limit * 2):
            if event.get("event_type") in ("bruteforce", "ddos", "blocked_ip"):
                attacks.append(event)
        return attacks[-limit:]


security_logger = SecurityEventLogger()
