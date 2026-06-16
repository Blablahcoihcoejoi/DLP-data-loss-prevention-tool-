# SecureProxy

Professional HTTP/HTTPS Data Loss Prevention (DLP) engine built on [mitmproxy](https://mitmproxy.org). Intercepts decrypted traffic locally, scans for sensitive data with risk scoring, and blocks or quarantines high-risk exfiltration attempts.

## Features

### Detection Engine
- Discord webhook & token detection
- Roblox `.ROBLOSECURITY` cookie detection
- AWS, GitHub, JWT, SSH private keys, generic API keys
- Password leaks, emails, Luhn-validated credit cards
- OAuth tokens, session cookies, database dumps
- Crypto seed phrases, `.env` files, PEM certificates
- Browser password exports, token dumps

### Content Parsing
Parses before scanning: JSON, form data, URL parameters, HTTP headers, cookies, XML, YAML, multipart uploads, GZIP payloads.

### File Inspection
Inspects ZIP, TXT, CSV, JSON uploads/downloads. Advanced support for PDF, DOCX, XLSX.

### Risk Scoring
Rules contribute weighted scores (configurable in `config/rules.yaml`):
- **100+** → block (403)
- **70+** → quarantine (451)
- **40+** → alert (logged + console)

### Correlation Engine
Multi-signal detection (e.g. Discord webhook + password + ZIP = CRITICAL).

### Anti-Evasion
Decodes Base64, hex, and URL-encoded blobs before scanning.

### Domain Intelligence
Allowlist, watchlist, and reputation scoring for file-sharing, webhooks, and C2 domains.

### Logging & Dashboard
Structured JSON logs with secret redaction. Live web dashboard at `http://127.0.0.1:8765`.

## Quick Start

```bash
cd SecureProxy
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Run the proxy
mitmdump -s Secure-Proxy.py

# Configure your system/browser to use proxy 127.0.0.1:8080
# Install mitmproxy CA cert for HTTPS decryption
```

## Configuration

Edit `config/rules.yaml` to tune rules, scores, thresholds, domains, and correlations without changing code.

```yaml
rules:
  discord_token:
    severity: critical
    score: 60

thresholds:
  block: 100
  quarantine: 70
  alert: 40
```

Override config path:
```bash
set SECUREPROXY_CONFIG=C:\path\to\custom_rules.yaml
mitmdump -s Secure-Proxy.py
```

## Testing

```bash
pytest -v
```

Sample fixtures in `tests/samples/` cover Discord tokens, AWS keys, Roblox cookies, and password dumps.

## Project Structure

```
SecureProxy/
├── Secure-Proxy.py          # mitmproxy entry point
├── config/rules.yaml        # Detection rules & thresholds
├── secureproxy/
│   ├── addon.py             # Request + response hooks
│   ├── detector.py          # Core scan engine + file inspector
│   ├── parser.py            # Content parsing
│   ├── scorer.py            # Risk scoring
│   ├── correlator.py        # Multi-signal correlation
│   ├── domains.py           # Domain intelligence
│   ├── evasion.py           # Anti-evasion decoding
│   ├── logger.py            # Async structured logging
│   └── stats.py             # Runtime statistics
├── dashboard/server.py      # Live web dashboard
└── tests/                   # pytest suite + samples
```

## Response Inspection

Both `request()` and `response()` hooks are active. Downloads containing credentials, malware payloads, or suspicious content are scored the same way as uploads.

## License

For authorized security research and personal DLP use only. Ensure you have permission to intercept traffic on monitored systems.
