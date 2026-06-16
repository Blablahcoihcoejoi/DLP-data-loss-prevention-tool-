"""Risk scoring engine and action determination."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from secureproxy.config import Config
from secureproxy.domains import DomainAssessment


class Action(str, Enum):
    ALLOW = "allowed"
    ALERT = "alert"
    QUARANTINE = "quarantined"
    BLOCK = "blocked"


@dataclass
class MatchResult:
    rule: str
    severity: str
    score: int
    source: str
    sample: str = ""


@dataclass
class RiskAssessment:
    total_score: int
    action: Action
    matches: list[MatchResult] = field(default_factory=list)
    correlations: list[str] = field(default_factory=list)
    domain_assessment: DomainAssessment | None = None
    domain_modifier: int = 0

    @property
    def highest_severity(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not self.matches:
            return "info"
        return max(self.matches, key=lambda m: order.get(m.severity, 0)).severity


class RiskScorer:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.thresholds = config.thresholds

    def score_matches(
        self,
        rule_hits: dict[str, list[tuple[str, str]]],
        correlation_names: list[str],
        correlation_bonus: int,
        domain_assessment: DomainAssessment | None = None,
    ) -> RiskAssessment:
        matches: list[MatchResult] = []
        total = 0

        for rule_name, hits in rule_hits.items():
            rule_cfg = self.config.rules.get(rule_name)
            if not rule_cfg or not rule_cfg.enabled:
                continue
            for source, sample in hits:
                matches.append(
                    MatchResult(
                        rule=rule_name,
                        severity=rule_cfg.severity,
                        score=rule_cfg.score,
                        source=source,
                        sample=sample[:120],
                    )
                )
                total += rule_cfg.score

        total += correlation_bonus

        domain_modifier = 0
        if domain_assessment is not None:
            from secureproxy.domains import DomainIntelligence

            di = DomainIntelligence(self.config)
            domain_modifier = di.domain_risk_modifier(domain_assessment)
            total += domain_modifier

        action = self._action_for_score(total, domain_assessment)
        return RiskAssessment(
            total_score=max(0, total),
            action=action,
            matches=matches,
            correlations=correlation_names,
            domain_assessment=domain_assessment,
            domain_modifier=domain_modifier,
        )

    def _action_for_score(
        self, score: int, domain_assessment: DomainAssessment | None
    ) -> Action:
        if domain_assessment and domain_assessment.on_allowlist and score < self.thresholds.get("block", 100):
            # Allowlisted domains reduce enforcement unless score is extreme
            if score < self.thresholds.get("quarantine", 70):
                return Action.ALLOW

        if score >= self.thresholds.get("block", 100):
            return Action.BLOCK
        if score >= self.thresholds.get("quarantine", 70):
            return Action.QUARANTINE
        if score >= self.thresholds.get("alert", 40):
            return Action.ALERT
        return Action.ALLOW
