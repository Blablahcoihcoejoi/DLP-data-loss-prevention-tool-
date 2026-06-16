"""Luhn algorithm for credit card validation."""

from __future__ import annotations

import re


def luhn_check(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def extract_luhn_valid_cards(text: str) -> list[str]:
    pattern = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    return [m.group() for m in pattern.finditer(text) if luhn_check(m.group())]
