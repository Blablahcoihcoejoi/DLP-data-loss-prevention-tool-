"""Anti-evasion decoding tests."""

import base64

from secureproxy.evasion import decode_base64, expand_text_for_scanning


def test_base64_decode():
    secret = "password=SuperSecret123!"
    encoded = base64.b64encode(secret.encode()).decode()
    blobs = decode_base64(f"data={encoded}")
    assert any(secret in b.decoded for b in blobs)


def test_expand_includes_decoded():
    secret = "AKIAIOSFODNN7EXAMPLE"
    encoded = base64.b64encode(secret.encode()).decode()
    expanded, blobs = expand_text_for_scanning(encoded)
    assert secret in expanded
    assert len(blobs) >= 1
