# DLP-data-loss-prevention-tool-

# Aegis Shield — Literal Network Lockdown

Aegis is a multi-threaded background network shield built to stop token stealers from cooking your PC. It sits in the middle of your network stack using mitmproxy and a local Flask dashboard, waiting to drop a massive ban hammer on malicious webhooks before they can even leave your computer. 

If a stealer tries to exfil your data to Discord, Aegis says "not today" and deletes the packet in a millisecond fr fr.

## Why it's Useful

* **Instant Intercept:** Captures outbound loopback traffic instantly. The stealer thinks it's talking to Discord, but it’s actually talking to a wall.
* **Stealer Proof:** Tested against live info-stealers. It leaves attackers with empty logs and a broken script while your tokens stay locked down.
* **Ghost Mode:** Compiles into a single, windowless .exe that runs completely hidden in the background so malware doesn't even know it's there.
* **Clean UI:** Has a local dark-mode Flask web dashboard (http://127.0.0.1:8765) so you can watch live traffic scroll past in real-time.
* **Custom Rules:** Uses a simple rules.yaml file so you can block any shady domain or regex pattern on the fly.

---

## How It Works (The Architecture)

Aegis uses layered defense to act as a massive perimeter wall:

1. **The Hook:** It automatically configures the Windows system proxy on boot, rerouting all traffic straight into the python engine.
2. **The Scan:** It checks the outbound URL against your rules.yaml file.
3. **The Drop:** If it sees a blocked signature (like a Discord webhook link), it drops the connection instantly. The attacker gets zero cookies, zero passwords, and a completely blank log.

---

## The Config (rules.yaml)

Drop your blocklists and flagged keywords right here:

```yaml
# Aegis Threat Matrix Config
block_domains:
  - "[discord.com/api/webhooks](https://discord.com/api/webhooks)"
  - "shady-exfil-domain.xyz"

flag_keywords:
  - "token"
  - "cookie"
  - "passwords"
