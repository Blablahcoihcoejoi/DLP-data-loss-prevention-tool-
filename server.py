"""Live dashboard for SecureProxy statistics."""

from __future__ import annotations

from flask import Flask, jsonify, render_template_string

from secureproxy.stats import Statistics

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureProxy Dashboard</title>
  <style>
    :root { --bg: #0f1419; --card: #1a2332; --accent: #00d4aa; --warn: #ffb020; --danger: #ff4757; --text: #e6edf3; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 1.5rem; }
    h1 { color: var(--accent); margin-bottom: 0.25rem; }
    .subtitle { color: #8b949e; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .card { background: var(--card); border-radius: 8px; padding: 1rem; border: 1px solid #30363d; }
    .card h3 { font-size: 0.75rem; text-transform: uppercase; color: #8b949e; margin-bottom: 0.5rem; }
    .card .value { font-size: 1.75rem; font-weight: 700; }
    .blocked { color: var(--danger); }
    .warn { color: var(--warn); }
    .section { margin-bottom: 1.5rem; }
    .section h2 { font-size: 1rem; margin-bottom: 0.75rem; color: var(--accent); }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #30363d; }
    .event { font-size: 0.8rem; padding: 0.5rem; border-bottom: 1px solid #21262d; }
    .event .action-blocked { color: var(--danger); }
    .event .action-quarantined { color: var(--warn); }
    .event .action-alert { color: #58a6ff; }
  </style>
</head>
<body>
  <h1>SecureProxy DLP Dashboard</h1>
  <p class="subtitle">Live threat monitoring — auto-refreshes every 3s</p>

  <div class="grid" id="stats-grid"></div>

  <div class="section">
    <h2>Top Domains</h2>
    <table><thead><tr><th>Domain</th><th>Hits</th></tr></thead><tbody id="top-domains"></tbody></table>
  </div>

  <div class="section">
    <h2>Top Rules</h2>
    <table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody id="top-rules"></tbody></table>
  </div>

  <div class="section">
    <h2>Recent Events</h2>
    <div id="recent-events"></div>
  </div>

  <script>
    async function refresh() {
      const r = await fetch('/api/stats');
      const d = await r.json();
      document.getElementById('stats-grid').innerHTML = `
        <div class="card"><h3>Inspected</h3><div class="value">${d.requests_inspected}</div></div>
        <div class="card"><h3>Blocked</h3><div class="value blocked">${d.requests_blocked}</div></div>
        <div class="card"><h3>Quarantined</h3><div class="value warn">${d.requests_quarantined}</div></div>
        <div class="card"><h3>Alerts</h3><div class="value">${d.requests_alerted}</div></div>
        <div class="card"><h3>Bytes Scanned</h3><div class="value">${(d.bytes_inspected/1024).toFixed(1)} KB</div></div>
        <div class="card"><h3>Req/min</h3><div class="value">${d.requests_per_minute.toFixed(1)}</div></div>
      `;
      document.getElementById('top-domains').innerHTML = d.top_domains.map(
        ([k,v]) => `<tr><td>${k}</td><td>${v}</td></tr>`
      ).join('') || '<tr><td colspan="2">No data yet</td></tr>';
      document.getElementById('top-rules').innerHTML = d.top_rules.map(
        ([k,v]) => `<tr><td>${k}</td><td>${v}</td></tr>`
      ).join('') || '<tr><td colspan="2">No data yet</td></tr>';
      document.getElementById('recent-events').innerHTML = d.recent_events.slice(0,20).map(e =>
        `<div class="event"><span class="action-${e.action}">[${e.action}]</span> ${e.severity} — ${e.rule} — ${e.url?.slice(0,80)}</div>`
      ).join('') || '<div class="event">No events yet</div>';
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


def create_app(stats: Statistics) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/stats")
    def api_stats():
        snap = stats.snapshot()
        return jsonify(
            {
                "requests_inspected": snap.requests_inspected,
                "requests_blocked": snap.requests_blocked,
                "requests_quarantined": snap.requests_quarantined,
                "requests_alerted": snap.requests_alerted,
                "bytes_inspected": snap.bytes_inspected,
                "top_domains": snap.top_domains,
                "top_rules": snap.top_rules,
                "recent_events": snap.recent_events,
                "requests_per_minute": snap.requests_per_minute,
                "uptime_seconds": snap.uptime_seconds,
            }
        )

    return app
