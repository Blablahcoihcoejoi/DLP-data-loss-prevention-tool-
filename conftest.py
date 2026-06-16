"""Shared test fixtures."""

from pathlib import Path

import pytest

from secureproxy.config import load_config
from secureproxy.detector import DetectionEngine, FileInspector, ScanResult
from secureproxy.parser import parse_flow_content


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parent.parent / "config" / "rules.yaml")


@pytest.fixture
def engine(config):
    return DetectionEngine(config)


@pytest.fixture
def samples_dir():
    return Path(__file__).resolve().parent / "samples"


def scan_text(engine: DetectionEngine, text: str, url: str = "https://example.com/") -> ScanResult:
    result = ScanResult()
    parsed = parse_flow_content(url, text, text.encode(), {}, "text/plain")
    engine.scan_parsed_content(parsed, result)
    engine.scan_body_bytes(text.encode(), "text/plain", result, FileInspector(engine))
    return result
