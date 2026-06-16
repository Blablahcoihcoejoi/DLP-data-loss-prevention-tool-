"""Domain intelligence: allowlist, watchlist, reputation scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from secureproxy.config import Config


@dataclass
class DomainAssessment:
    domain: str
    on_allowlist: bool
    on_watchlist: bool
    reputation_tags: list[str]
    reputation_score: int


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _domain_matches(domain: str, entry: str) -> bool:
    entry = entry.lower().strip()
    domain = domain.lower()
    return domain == entry or domain.endswith("." + entry)


class DomainIntelligence:
    def __init__(self, config: Config) -> None:
        self.allowlist: list[str] = config.domains.get("allowlist", [])
        self.watchlist: list[str] = config.domains.get("watchlist", [])
        reputation = config.domains.get("reputation", {})
        if isinstance(reputation, dict):
            self.reputation_map: dict[str, list[str]] = reputation
        else:
            self.reputation_map = {}

    def assess(self, url: str) -> DomainAssessment:
        domain = extract_domain(url)
        on_allowlist = any(_domain_matches(domain, d) for d in self.allowlist)
        on_watchlist = any(_domain_matches(domain, d) for d in self.watchlist)

        tags: list[str] = []
        rep_score = 0
        for tag, domains in self.reputation_map.items():
            if any(_domain_matches(domain, d) for d in domains):
                tags.append(tag)
                rep_score += {"file_sharing": 15, "webhook_services": 20, "malware_c2": 40}.get(
                    tag, 10
                )

        # Watchlist path patterns (e.g. discord webhooks)
        if re.search(r"discord(?:app)?\.com/api/webhooks", url, re.I):
            if "webhook_services" not in tags:
                tags.append("webhook_services")
                rep_score += 20

        return DomainAssessment(
            domain=domain,
            on_allowlist=on_allowlist,
            on_watchlist=on_watchlist,
            reputation_tags=tags,
            reputation_score=rep_score,
        )

    def domain_risk_modifier(self, assessment: DomainAssessment) -> int:
        if assessment.on_allowlist:
            return -30
        return assessment.reputation_score + (10 if assessment.on_watchlist else 0)
