"""Content parser tests."""

import json

from secureproxy.parser import parse_flow_content, parse_json_body, parse_url_params


def test_json_parsing():
    body = json.dumps({"password": "secret123", "user": "admin"})
    parsed = parse_json_body(body)
    keys = [s for s, _ in parsed.segments]
    assert any("password" in k for k in keys)


def test_url_params():
    parsed = parse_url_params("https://example.com/login?password=secret123&user=admin")
    values = dict(parsed.segments)
    assert any("secret" in v for _, v in parsed.segments)


def test_headers_and_cookies():
    headers = {"Cookie": "session=abc123; .ROBLOSECURITY=fakecookievalue1234567890"}
    parsed = parse_flow_content(
        "https://example.com",
        "",
        b"",
        headers,
    )
    sources = [s for s, _ in parsed.segments]
    assert any("cookie" in s.lower() for s in sources)
