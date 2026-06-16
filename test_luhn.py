"""Luhn validation tests."""

from secureproxy.luhn import luhn_check, extract_luhn_valid_cards


def test_valid_visa():
    assert luhn_check("4111111111111111") is True


def test_invalid_card():
    assert luhn_check("4111111111111112") is False


def test_extract_valid_only():
    text = "card: 4111111111111111 and fake 1234-5678-9012-3456"
    cards = extract_luhn_valid_cards(text)
    assert "4111111111111111" in cards
    assert "1234-5678-9012-3456" not in cards
