#!/usr/bin/env python3
"""
SecureProxy — Professional HTTP/HTTPS Data Loss Prevention Engine
=================================================================
Intercepts and inspects decrypted outbound/inbound traffic via mitmproxy.

Usage:
  mitmdump -s Secure-Proxy.py
  mitmproxy -s Secure-Proxy.py

Configure rules in config/rules.yaml
Dashboard: http://127.0.0.1:8765 (when enabled)
"""

from secureproxy.addon import addons  # noqa: F401 — mitmproxy entry point
