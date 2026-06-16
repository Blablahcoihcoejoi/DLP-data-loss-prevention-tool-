"""Regex detection patterns mapped to rule names."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternSpec:
    rule: str
    pattern: re.Pattern[str]
    validator: str | None = None


PATTERNS: list[PatternSpec] = [
    PatternSpec(
        "discord_token",
        re.compile(r"\b[A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}\b"),
    ),
    PatternSpec(
        "discord_webhook",
        re.compile(
            r"https?://(?:discord(?:app)?\.com|discord\.com)/api/webhooks/\d+/[A-Za-z0-9\-_]+",
            re.I,
        ),
    ),
    PatternSpec(
        "roblox_cookie",
        re.compile(r"(?:\.ROBLOSECURITY|roblosecurity)[=:\s]+[^\s;]{20,}", re.I),
    ),
    PatternSpec(
        "aws_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    PatternSpec(
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ),
    PatternSpec(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    ),
    PatternSpec(
        "ssh_private_key",
        re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----",
            re.I,
        ),
    ),
    PatternSpec(
        "generic_api_key",
        re.compile(
            r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key)[=:\s\"']+[A-Za-z0-9\-_\.]{16,}",
            re.I,
        ),
    ),
    PatternSpec(
        "password_leak",
        re.compile(
            r"\b(?:password|passwd|pwd|pass_token|passphrase)[=:\s\"']+\S{6,}",
            re.I,
        ),
    ),
    PatternSpec(
        "email_address",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    PatternSpec(
        "credit_card",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        validator="luhn",
    ),
    PatternSpec(
        "oauth_token",
        re.compile(
            r"(?:oauth[_-]?token|refresh[_-]?token|access[_-]?token)[=:\s\"']+[A-Za-z0-9\-_\.]{20,}",
            re.I,
        ),
    ),
    PatternSpec(
        "session_cookie",
        re.compile(
            r"(?:session[_-]?id|PHPSESSID|JSESSIONID|connect\.sid)[=:\s\"']+[A-Za-z0-9\-_\.]{16,}",
            re.I,
        ),
    ),
    PatternSpec(
        "database_dump",
        re.compile(
            r"(?:INSERT INTO|CREATE TABLE|mysqldump|pg_dump|sqlite_master).{0,200}(?:password|token|secret)",
            re.I | re.S,
        ),
    ),
    PatternSpec(
        "crypto_seed_phrase",
        re.compile(
            r"\b(?:(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})\b",
            re.I,
        ),
        validator="bip39_word_count",
    ),
    PatternSpec(
        "env_file",
        re.compile(
            r"(?:^|\n)(?:[A-Z][A-Z0-9_]*=(?:[^\n\r]{4,}))(?:\n[A-Z][A-Z0-9_]*=[^\n\r]+){2,}",
            re.M,
        ),
    ),
    PatternSpec(
        "pem_certificate",
        re.compile(
            r"-----BEGIN (?:CERTIFICATE|RSA PUBLIC KEY|EC PUBLIC KEY)-----",
            re.I,
        ),
    ),
    PatternSpec(
        "browser_password_export",
        re.compile(
            r"(?:\"url\"\s*:\s*\"https?://|Origin\s*:\s*https?://).{0,500}(?:\"username\"|\"password\"|login_user|login_pass)",
            re.I | re.S,
        ),
    ),
    PatternSpec(
        "token_dump",
        re.compile(
            r"(?:token|discord|roblox|steam|minecraft).{0,50}(?:token|cookie|password).{0,200}(?:\n|\r\n){3,}",
            re.I | re.S,
        ),
    ),
]

EVASION_PATTERNS = {
    "base64_encoded_secret": re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    "hex_encoded_secret": re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){20,}\b"),
    "url_encoded_secret": re.compile(r"(?:%[0-9A-Fa-f]{2}){10,}"),
}
