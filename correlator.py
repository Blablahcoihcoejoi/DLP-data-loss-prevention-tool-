"""Multi-signal correlation engine."""

from __future__ import annotations

from secureproxy.config import Config, CorrelationRule


class Correlator:
    def __init__(self, config: Config) -> None:
        self.rules: list[CorrelationRule] = config.correlations

    def evaluate(self, triggered_rules: set[str]) -> tuple[list[str], int, str]:
        """
        Return (correlation_names, bonus_score, highest_severity).
        A correlation fires when ALL signals in a rule are present.
        """
        names: list[str] = []
        bonus = 0
        severity = "medium"

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for rule in self.rules:
            if all(signal in triggered_rules for signal in rule.signals):
                names.append(rule.name)
                bonus += rule.bonus_score
                if severity_order.get(rule.severity, 0) > severity_order.get(severity, 0):
                    severity = rule.severity

        return names, bonus, severity
