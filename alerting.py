"""Optional alerting: email and local notifications."""

from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from typing import Any

from secureproxy.scorer import RiskAssessment


def send_email_alert(
    assessment: RiskAssessment,
    url: str,
    smtp_config: dict[str, Any],
) -> None:
    if not smtp_config.get("enabled"):
        return

    recipients = smtp_config.get("to", [])
    if not recipients:
        return

    subject = f"[SecureProxy] {assessment.action.value.upper()} — {assessment.highest_severity}"
    body = (
        f"Action: {assessment.action.value}\n"
        f"Severity: {assessment.highest_severity}\n"
        f"Risk Score: {assessment.total_score}\n"
        f"URL: {url}\n"
        f"Rules: {', '.join(m.rule for m in assessment.matches)}\n"
        f"Correlations: {', '.join(assessment.correlations) or 'none'}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_config.get("from", "secureproxy@localhost")
    msg["To"] = ", ".join(recipients)

    host = smtp_config.get("smtp_host", "localhost")
    port = int(smtp_config.get("smtp_port", 587))
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        if smtp_config.get("username"):
            server.login(smtp_config["username"], smtp_config.get("password", ""))
        server.sendmail(msg["From"], recipients, msg.as_string())
