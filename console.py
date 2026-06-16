"""Console output for live monitoring."""

from __future__ import annotations

from colorama import Fore, Style, init as colorama_init

from secureproxy.scorer import Action, RiskAssessment

colorama_init(autoreset=True)

SEVERITY_COLORS = {
    "critical": Fore.RED,
    "high": Fore.MAGENTA,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}

ACTION_COLORS = {
    Action.BLOCK: Fore.RED,
    Action.QUARANTINE: Fore.MAGENTA,
    Action.ALERT: Fore.YELLOW,
    Action.ALLOW: Fore.GREEN,
}


def print_banner(log_file: str, dashboard_url: str | None = None) -> None:
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 54}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  SecureProxy DLP Engine v2.0 — ACTIVE")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 54}")
    print(f"{Fore.YELLOW}  Monitoring decrypted HTTP/HTTPS streams")
    print(f"{Fore.YELLOW}  Alerts: {log_file}")
    if dashboard_url:
        print(f"{Fore.YELLOW}  Dashboard: {dashboard_url}")
    print()


def print_assessment(direction: str, url: str, assessment: RiskAssessment) -> None:
    if assessment.action == Action.ALLOW and not assessment.matches:
        return

    color = ACTION_COLORS.get(assessment.action, Fore.WHITE)
    sev_color = SEVERITY_COLORS.get(assessment.highest_severity, Fore.WHITE)

    print(f"{color}{Style.BRIGHT}{'!' * 60}")
    print(
        f"{color}{Style.BRIGHT}[{assessment.action.value.upper()}] {direction} — "
        f"{sev_color}{assessment.highest_severity}"
    )
    print(f"{Fore.YELLOW}  URL        : {url}")
    print(f"{Fore.YELLOW}  Risk Score : {assessment.total_score}")
    rules = ", ".join(m.rule for m in assessment.matches)
    print(f"{Fore.MAGENTA}  Rules      : {rules or 'none'}")
    if assessment.correlations:
        print(f"{Fore.RED}  Correlation: {', '.join(assessment.correlations)}")
    if assessment.domain_assessment:
        da = assessment.domain_assessment
        tags = ", ".join(da.reputation_tags) or "none"
        print(f"{Fore.CYAN}  Domain     : {da.domain} (rep: {da.reputation_score}, tags: {tags})")
    print(f"{color}{Style.BRIGHT}{'!' * 60}\n")
