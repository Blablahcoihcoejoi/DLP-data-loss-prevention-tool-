"""Redaction tests."""

from secureproxy.redactor import redact_secret, redact_text


def test_redact_secret():
    assert redact_secret("abcdef1234567890") == "abcd********7890"


def test_redact_short():
    assert redact_secret("abc") == "***"


def test_redact_in_text():
    text = "password=SuperSecretPassword123"
    redacted = redact_text(text)
    assert "SuperSecretPassword123" not in redacted
    assert "pass" in redacted
