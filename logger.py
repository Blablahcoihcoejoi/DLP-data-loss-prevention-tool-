"""Structured async logging with secret redaction."""

from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureproxy.redactor import redact_text
from secureproxy.scorer import RiskAssessment


class AlertLogger:
    def __init__(
        self,
        log_path: str | Path,
        redact: bool = True,
        redact_keep: int = 4,
        async_mode: bool = True,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.redact = redact
        self.redact_keep = redact_keep
        self.async_mode = async_mode
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._worker: threading.Thread | None = None
        if async_mode:
            self._start_worker()

    def _start_worker(self) -> None:
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()

    def _process_queue(self) -> None:
        while True:
            entry = self._queue.get()
            if entry is None:
                break
            self._write_entry(entry)

    def _write_entry(self, entry: dict[str, Any]) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log_event(
        self,
        *,
        direction: str,
        url: str,
        assessment: RiskAssessment,
        content_preview: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        primary_rule = assessment.matches[0].rule if assessment.matches else "none"
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "url": url,
            "severity": assessment.highest_severity,
            "rule": primary_rule,
            "rules": [m.rule for m in assessment.matches],
            "action": assessment.action.value,
            "risk_score": assessment.total_score,
            "correlations": assessment.correlations,
            "domain": assessment.domain_assessment.domain if assessment.domain_assessment else "",
            "content_preview": (
                redact_text(content_preview[:300], self.redact_keep)
                if self.redact
                else content_preview[:300]
            ),
        }
        if extra:
            entry.update(extra)

        if self.async_mode:
            self._queue.put(entry)
        else:
            self._write_entry(entry)

        return entry

    def shutdown(self) -> None:
        if self.async_mode and self._worker:
            self._queue.put(None)
            self._worker.join(timeout=2)
