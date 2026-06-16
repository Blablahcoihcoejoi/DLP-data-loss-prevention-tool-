"""Mitmproxy addon — request and response inspection."""

from __future__ import annotations

import threading
from pathlib import Path

import mitmproxy.http

from secureproxy.config import Config, load_config
from secureproxy.console import print_assessment, print_banner
from secureproxy.correlator import Correlator
from secureproxy.detector import DetectionEngine, FileInspector, ScanResult
from secureproxy.domains import DomainIntelligence, extract_domain
from secureproxy.logger import AlertLogger
from secureproxy.parser import parse_flow_content
from secureproxy.scorer import Action, RiskScorer
from secureproxy.stats import Statistics


class SecureProxyAddon:
    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config: Config = load_config(config_path)
        self.engine = DetectionEngine(self.config)
        self.file_inspector = FileInspector(self.engine)
        self.scorer = RiskScorer(self.config)
        self.correlator = Correlator(self.config)
        self.domains = DomainIntelligence(self.config)
        self.stats = Statistics()

        log_cfg = self.config.logging
        log_path = log_cfg.get("file", "logs/secureproxy_alerts.log")
        self.logger = AlertLogger(
            log_path=log_path,
            redact=log_cfg.get("redact", True),
            redact_keep=log_cfg.get("redact_keep_chars", 4),
            async_mode=log_cfg.get("async", True),
        )

        self._dashboard_thread: threading.Thread | None = None
        self._dashboard_url: str | None = None
        self._start_dashboard()

        print_banner(log_path, self._dashboard_url)

    def _start_dashboard(self) -> None:
        dash_cfg = self.config.dashboard
        if not dash_cfg.get("enabled", True):
            return
        host = dash_cfg.get("host", "127.0.0.1")
        port = dash_cfg.get("port", 8765)
        self._dashboard_url = f"http://{host}:{port}"

        def run() -> None:
            from dashboard.server import create_app

            app = create_app(self.stats)
            app.run(host=host, port=port, debug=False, use_reloader=False)

        self._dashboard_thread = threading.Thread(target=run, daemon=True)
        self._dashboard_thread.start()

    def _inspect(
        self,
        flow: mitmproxy.http.HTTPFlow,
        direction: str,
    ) -> None:
        if direction == "request":
            url = flow.request.pretty_url
            headers = flow.request.headers
            content_type = flow.request.headers.get("content-type", "")
            try:
                body_text = flow.request.get_text(strict=False) or ""
            except Exception:
                body_text = ""
            body_bytes = flow.request.raw_content or b""
        else:
            url = flow.request.pretty_url
            headers = flow.response.headers if flow.response else {}
            content_type = flow.response.headers.get("content-type", "") if flow.response else ""
            try:
                body_text = flow.response.get_text(strict=False) if flow.response else ""
            except Exception:
                body_text = ""
            body_bytes = flow.response.raw_content if flow.response else b""

        default_max = self.config.body_limits.get("default_max", 1_048_576)
        if len(body_bytes) > default_max:
            body_bytes = body_bytes[:default_max]

        parsed = parse_flow_content(url, body_text, body_bytes, headers, content_type)
        scan_result = ScanResult()
        engine = DetectionEngine(self.config)
        inspector = FileInspector(engine)
        engine.scan_parsed_content(parsed, scan_result)
        engine.scan_body_bytes(body_bytes, content_type, scan_result, inspector)

        self.stats.record_inspection(scan_result.bytes_scanned)

        if not scan_result.triggered_rules:
            domain_assessment = self.domains.assess(url)
            if domain_assessment.reputation_score == 0:
                return

        domain_assessment = self.domains.assess(url)
        corr_names, corr_bonus, _ = self.correlator.evaluate(scan_result.triggered_rules)
        assessment = self.scorer.score_matches(
            scan_result.rule_hits,
            corr_names,
            corr_bonus,
            domain_assessment,
        )

        if assessment.action == Action.ALLOW and not scan_result.triggered_rules:
            return

        preview = parsed.all_text()[:500]
        log_entry = self.logger.log_event(
            direction=direction,
            url=url,
            assessment=assessment,
            content_preview=preview,
            extra={"bytes_scanned": scan_result.bytes_scanned, "truncated": scan_result.truncated},
        )

        domain = extract_domain(url)
        self.stats.record_action(
            assessment.action.value,
            domain,
            [m.rule for m in assessment.matches],
            log_entry,
        )

        print_assessment(direction.upper(), url, assessment)
        self._maybe_notify(assessment, url)
        self._maybe_email(assessment, url)

        if direction == "request":
            self._apply_action(flow, assessment)

    def _apply_action(self, flow: mitmproxy.http.HTTPFlow, assessment) -> None:
        if assessment.action == Action.BLOCK:
            flow.response = mitmproxy.http.Response.make(
                403,
                b"Blocked by SecureProxy Data Loss Prevention Engine.",
                {"Content-Type": "text/plain", "X-SecureProxy-Action": "blocked"},
            )
        elif assessment.action == Action.QUARANTINE:
            flow.response = mitmproxy.http.Response.make(
                451,
                b"Quarantined by SecureProxy - suspicious data detected.",
                {"Content-Type": "text/plain", "X-SecureProxy-Action": "quarantined"},
            )
    def _maybe_email(self, assessment, url: str) -> None:
        if assessment.action.value not in ("blocked", "quarantined"):
            return
        try:
            from secureproxy.alerting import send_email_alert

            send_email_alert(assessment, url, self.config.alerting.get("email", {}))
        except Exception:
            pass

    def _maybe_notify(self, assessment, url: str) -> None:
        alerting = self.config.alerting
        if alerting.get("local_notifications") and assessment.action in (
            Action.BLOCK,
            Action.QUARANTINE,
        ):
            try:
                from plyer import notification  # optional dependency

                notification.notify(
                    title=f"SecureProxy: {assessment.action.value}",
                    message=f"{assessment.highest_severity} — {url[:80]}",
                    timeout=5,
                )
            except Exception:
                pass

    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        self._inspect(flow, "request")

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        self._inspect(flow, "response")

    def done(self) -> None:
        self.logger.shutdown()


addons = [SecureProxyAddon()]
