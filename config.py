"""Configuration loader for SecureProxy."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


@dataclass
class RuleConfig:
    enabled: bool
    severity: str
    score: int
    description: str


@dataclass
class CorrelationRule:
    name: str
    description: str
    signals: list[str]
    bonus_score: int
    severity: str


@dataclass
class Config:
    rules: dict[str, RuleConfig]
    thresholds: dict[str, int]
    body_limits: dict[str, int]
    domains: dict[str, list[str] | dict[str, list[str]]]
    correlations: list[CorrelationRule]
    logging: dict[str, Any]
    alerting: dict[str, Any]
    dashboard: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def load_config(path: str | Path | None = None) -> Config:
    config_path = Path(path or os.environ.get("SECUREPROXY_CONFIG", DEFAULT_CONFIG_PATH))
    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    rules = {
        name: RuleConfig(
            enabled=spec.get("enabled", True),
            severity=spec.get("severity", "medium"),
            score=spec.get("score", 10),
            description=spec.get("description", name),
        )
        for name, spec in raw.get("rules", {}).items()
    }

    correlations = [
        CorrelationRule(
            name=c["name"],
            description=c.get("description", ""),
            signals=c["signals"],
            bonus_score=c.get("bonus_score", 30),
            severity=c.get("severity", "critical"),
        )
        for c in raw.get("correlations", [])
    ]

    return Config(
        rules=rules,
        thresholds=raw.get("thresholds", {"block": 100, "quarantine": 70, "alert": 40}),
        body_limits=raw.get(
            "body_limits",
            {"scan_max": 10_485_760, "warn_max": 5_242_880, "default_max": 1_048_576},
        ),
        domains=raw.get("domains", {}),
        correlations=correlations,
        logging=raw.get("logging", {}),
        alerting=raw.get("alerting", {}),
        dashboard=raw.get("dashboard", {"enabled": True, "host": "127.0.0.1", "port": 8765}),
        raw=raw,
    )
