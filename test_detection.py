"""Detection engine tests."""

from pathlib import Path

from secureproxy.correlator import Correlator
from secureproxy.scorer import Action, RiskScorer
from tests.conftest import scan_text


def test_discord_token_detection(engine, samples_dir):
    text = (samples_dir / "discord_token.txt").read_text()
    result = scan_text(engine, text)
    assert "discord_token" in result.triggered_rules


def test_aws_key_detection(engine, samples_dir):
    text = (samples_dir / "aws_key.txt").read_text()
    result = scan_text(engine, text)
    assert "aws_key" in result.triggered_rules


def test_roblox_cookie_detection(engine, samples_dir):
    text = (samples_dir / "roblox_cookie.txt").read_text()
    result = scan_text(engine, text)
    assert "roblox_cookie" in result.triggered_rules


def test_password_dump_detection(engine, samples_dir):
    text = (samples_dir / "password_dump.txt").read_text()
    result = scan_text(engine, text)
    assert "password_leak" in result.triggered_rules


def test_discord_webhook_in_url(engine):
    url = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz"
    result = scan_text(engine, "", url=url)
    assert "discord_webhook" in result.triggered_rules


def test_github_token_detection(engine):
    text = "token=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
    result = scan_text(engine, text)
    assert "github_token" in result.triggered_rules


def test_jwt_detection(engine):
    text = "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    result = scan_text(engine, text)
    assert "jwt" in result.triggered_rules


def test_ssh_key_detection(engine):
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU"
    result = scan_text(engine, text)
    assert "ssh_private_key" in result.triggered_rules


def test_risk_scoring_blocks_high_risk(config, engine):
    text = (Path(__file__).parent / "samples" / "discord_token.txt").read_text()
    url = "https://discord.com/api/webhooks/999/abcdefgh"
    result = scan_text(engine, text, url=url)
    scorer = RiskScorer(config)
    correlator = Correlator(config)
    names, bonus, _ = correlator.evaluate(result.triggered_rules)
    assessment = scorer.score_matches(result.rule_hits, names, bonus)
    assert assessment.total_score >= config.thresholds["alert"]
    assert assessment.action in (Action.BLOCK, Action.QUARANTINE, Action.ALERT)


def test_correlation_stealer_exfiltration(config, engine):
    url = "https://discord.com/api/webhooks/123/abc"
    text = "password=SuperSecret123!\n" + (Path(__file__).parent / "samples" / "discord_token.txt").read_text()
    result = scan_text(engine, text, url=url)
    correlator = Correlator(config)
    names, bonus, _ = correlator.evaluate(result.triggered_rules)
    assert "stealer_exfiltration" in names
    assert bonus > 0
