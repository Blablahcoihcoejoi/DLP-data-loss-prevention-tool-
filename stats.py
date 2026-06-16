"""Runtime statistics for dashboard and reporting."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StatsSnapshot:
    requests_inspected: int = 0
    requests_blocked: int = 0
    requests_quarantined: int = 0
    requests_alerted: int = 0
    bytes_inspected: int = 0
    top_domains: list[tuple[str, int]] = field(default_factory=list)
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    requests_per_minute: float = 0.0
    uptime_seconds: float = 0.0


class Statistics:
    def __init__(self, recent_limit: int = 100) -> None:
        self._lock = threading.Lock()
        self._start = time.time()
        self.requests_inspected = 0
        self.requests_blocked = 0
        self.requests_quarantined = 0
        self.requests_alerted = 0
        self.bytes_inspected = 0
        self.domain_counts: Counter[str] = Counter()
        self.rule_counts: Counter[str] = Counter()
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=recent_limit)
        self._request_timestamps: deque[float] = deque(maxlen=500)

    def record_inspection(self, bytes_count: int = 0) -> None:
        with self._lock:
            self.requests_inspected += 1
            self.bytes_inspected += bytes_count
            self._request_timestamps.append(time.time())

    def record_action(
        self, action: str, domain: str, rules: list[str], event: dict[str, Any]
    ) -> None:
        with self._lock:
            if action == "blocked":
                self.requests_blocked += 1
            elif action == "quarantined":
                self.requests_quarantined += 1
            elif action == "alert":
                self.requests_alerted += 1

            if domain:
                self.domain_counts[domain] += 1
            for rule in rules:
                self.rule_counts[rule] += 1
            self.recent_events.appendleft(event)

    def snapshot(self) -> StatsSnapshot:
        with self._lock:
            now = time.time()
            minute_ago = now - 60
            rpm = sum(1 for t in self._request_timestamps if t >= minute_ago)
            return StatsSnapshot(
                requests_inspected=self.requests_inspected,
                requests_blocked=self.requests_blocked,
                requests_quarantined=self.requests_quarantined,
                requests_alerted=self.requests_alerted,
                bytes_inspected=self.bytes_inspected,
                top_domains=self.domain_counts.most_common(10),
                top_rules=self.rule_counts.most_common(10),
                recent_events=list(self.recent_events),
                requests_per_minute=float(rpm),
                uptime_seconds=now - self._start,
            )
