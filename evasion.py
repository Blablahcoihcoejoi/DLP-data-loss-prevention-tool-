"""Anti-evasion decoding: base64, hex, URL encoding."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass


@dataclass
class DecodedBlob:
    encoding: str
    original: str
    decoded: str


def decode_base64(text: str) -> list[DecodedBlob]:
    results: list[DecodedBlob] = []
    for match in re.finditer(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", text):
        blob = match.group()
        try:
            decoded_bytes = base64.b64decode(blob, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded) >= 8 and decoded.isprintable():
                results.append(DecodedBlob("base64", blob, decoded))
        except (binascii.Error, ValueError):
            continue
    return results


def decode_hex(text: str) -> list[DecodedBlob]:
    results: list[DecodedBlob] = []
    for match in re.finditer(r"\b(?:0x)?((?:[0-9a-fA-F]{2}){20,})\b", text):
        hex_str = match.group(1)
        try:
            decoded_bytes = bytes.fromhex(hex_str)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded) >= 8:
                results.append(DecodedBlob("hex", match.group(), decoded))
        except ValueError:
            continue
    return results


def decode_url_encoded(text: str) -> list[DecodedBlob]:
    results: list[DecodedBlob] = []
    for match in re.finditer(r"(?:%[0-9A-Fa-f]{2}){10,}", text):
        blob = match.group()
        try:
            decoded = urllib.parse.unquote(blob)
            if decoded != blob and len(decoded) >= 8:
                results.append(DecodedBlob("url", blob, decoded))
        except Exception:
            continue
    return results


def expand_text_for_scanning(text: str) -> tuple[str, list[DecodedBlob]]:
    blobs: list[DecodedBlob] = []
    blobs.extend(decode_base64(text))
    blobs.extend(decode_hex(text))
    blobs.extend(decode_url_encoded(text))

    parts = [text]
    for blob in blobs:
        parts.append(blob.decoded)

    return "\n".join(parts), blobs
