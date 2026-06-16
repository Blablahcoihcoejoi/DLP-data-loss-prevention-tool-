"""Content parsing: JSON, form data, URL params, headers, cookies, XML, YAML, multipart."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from email import message_from_bytes
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


@dataclass
class ParsedContent:
    segments: list[tuple[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def all_text(self) -> str:
        return "\n".join(text for _, text in self.segments if text)


def _flatten_json(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            pairs.extend(_flatten_json(v, key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            pairs.extend(_flatten_json(item, f"{prefix}[{i}]"))
    elif obj is not None:
        pairs.append((prefix or "value", str(obj)))
    return pairs


def parse_url_params(url: str) -> ParsedContent:
    parsed = ParsedContent()
    if "?" not in url:
        return parsed
    query = url.split("?", 1)[1]
    for key, values in urllib.parse.parse_qs(query, keep_blank_values=True).items():
        for val in values:
            parsed.segments.append((f"url_param:{key}", val))
    return parsed


def parse_json_body(text: str) -> ParsedContent:
    parsed = ParsedContent()
    try:
        data = json.loads(text)
        for key, val in _flatten_json(data):
            parsed.segments.append((f"json:{key}", val))
        parsed.metadata["format"] = "json"
    except (json.JSONDecodeError, TypeError):
        pass
    return parsed


def parse_form_body(text: str, content_type: str = "") -> ParsedContent:
    parsed = ParsedContent()
    if "application/x-www-form-urlencoded" not in content_type and "=" in text:
        # Heuristic fallback
        pass
    try:
        for key, values in urllib.parse.parse_qs(text, keep_blank_values=True).items():
            for val in values:
                parsed.segments.append((f"form:{key}", val))
        if parsed.segments:
            parsed.metadata["format"] = "form"
    except Exception:
        pass
    return parsed


def parse_headers(headers: Any) -> ParsedContent:
    parsed = ParsedContent()
    if headers is None:
        return parsed
    items = headers.items() if hasattr(headers, "items") else headers
    for name, value in items:
        name_str = name.decode() if isinstance(name, bytes) else str(name)
        val_str = value.decode() if isinstance(value, bytes) else str(value)
        parsed.segments.append((f"header:{name_str}", val_str))
        if name_str.lower() == "cookie":
            for part in val_str.split(";"):
                part = part.strip()
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    parsed.segments.append((f"cookie:{ck.strip()}", cv.strip()))
    return parsed


def parse_cookies(cookie_header: str) -> ParsedContent:
    parsed = ParsedContent()
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            ck, cv = part.split("=", 1)
            parsed.segments.append((f"cookie:{ck.strip()}", cv.strip()))
    return parsed


def parse_yaml_body(text: str) -> ParsedContent:
    parsed = ParsedContent()
    if yaml is None:
        return parsed
    try:
        data = yaml.safe_load(text)
        if isinstance(data, (dict, list)):
            for key, val in _flatten_json(data):
                parsed.segments.append((f"yaml:{key}", val))
            parsed.metadata["format"] = "yaml"
    except Exception:
        pass
    return parsed


def parse_xml_body(text: str) -> ParsedContent:
    parsed = ParsedContent()
    # Lightweight tag/value extraction (no heavy XML dependency)
    for match in re.finditer(r"<([A-Za-z0-9_\-]+)[^>]*>([^<]{1,500})</\1>", text):
        parsed.segments.append((f"xml:{match.group(1)}", match.group(2)))
    if parsed.segments:
        parsed.metadata["format"] = "xml"
    return parsed


def parse_multipart(body: bytes, content_type: str) -> ParsedContent:
    parsed = ParsedContent()
    if "multipart/" not in content_type:
        return parsed
    try:
        msg = message_from_bytes(
            b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
        )
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                name = part.get_param("name", header="content-disposition") or "part"
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                label = f"multipart:{name}"
                if filename:
                    label = f"multipart:file:{filename}"
                try:
                    text = payload.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""
                parsed.segments.append((label, text))
            parsed.metadata["format"] = "multipart"
    except Exception:
        pass
    return parsed


def parse_flow_content(
    url: str,
    body_text: str,
    body_bytes: bytes,
    headers: Any,
    content_type: str = "",
) -> ParsedContent:
    """Aggregate all parseable content from a flow into scannable segments."""
    combined = ParsedContent()

    combined.segments.append(("url", url))
    combined.segments.extend(parse_url_params(url).segments)
    combined.segments.extend(parse_headers(headers).segments)

    if body_text:
        combined.segments.append(("body_raw", body_text))
        combined.segments.extend(parse_json_body(body_text).segments)
        combined.segments.extend(parse_form_body(body_text, content_type).segments)
        combined.segments.extend(parse_yaml_body(body_text).segments)
        combined.segments.extend(parse_xml_body(body_text).segments)

    if body_bytes and "multipart/" in content_type:
        combined.segments.extend(parse_multipart(body_bytes, content_type).segments)

    return combined
