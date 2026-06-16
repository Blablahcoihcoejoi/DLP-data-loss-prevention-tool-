"""Secret redaction for logs and console output."""

from __future__ import annotations

import re


def redact_secret(value: str, keep: int = 4) -> str:
    if not value:
        return value
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + ("*" * (len(value) - keep * 2)) + value[-keep:]


def redact_text(text: str, keep: int = 4) -> str:
    """Redact likely secrets in free-form text."""
    patterns = [
        (r"\b[A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}\b", "discord_token"),
        (r"\bAKIA[0-9A-Z]{16}\b", "aws_key"),
        (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "github_token"),
        (r"(password|passwd|pwd)[=:\s\"']+\S+", "password"),
        (r"(?:\.ROBLOSECURITY|roblosecurity)[=:\s]+[^\s;]+", "roblox"),
    ]
    result = text
    for pattern, _ in patterns:
        result = re.sub(
            pattern,
            lambda m: redact_match(m.group(), keep),
            result,
            flags=re.I,
        )
    return result


def redact_match(match: str, keep: int = 4) -> str:
    if "=" in match or ":" in match:
        sep_idx = max(match.rfind("="), match.rfind(":"))
        prefix = match[: sep_idx + 1]
        secret = match[sep_idx + 1 :].strip().strip("'\"")
        return prefix + redact_secret(secret, keep)
    return redact_secret(match, keep)
