#!/usr/bin/env python3
"""
Cowrie Honeypot Log Analyzer
Parses cowrie.json* logs and generates an interactive HTML dashboard.
Usage: python3 analyze.py [--log-dir /path/to/logs] [--output dashboard.html]
"""

import json
import argparse
import glob
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_LOG_DIR = "/home/cowrie/cowrie/var/log/cowrie"
DEFAULT_OUTPUT  = "output/dashboard.html"
LOG_PATTERN     = "cowrie.json*"

# ── Loader ────────────────────────────────────────────────────────────────────
def load_logs(log_dir: str) -> list[dict]:
    events = []
    files = sorted(glob.glob(os.path.join(log_dir, LOG_PATTERN)))
    if not files:
        raise FileNotFoundError(f"No cowrie.json* files found in {log_dir}")
    for path in files:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    print(f"[+] Loaded {len(events):,} events from {len(files)} files")
    return events

# ── Analysis ──────────────────────────────────────────────────────────────────
def analyze(events: list[dict]) -> dict:
    connects        = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    logins_ok       = [e for e in events if e.get("eventid") == "cowrie.login.success"]
    logins_fail     = [e for e in events if e.get("eventid") == "cowrie.login.failed"]
    commands        = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    downloads       = [e for e in events if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_download.failed")]

    # Unique IPs
    all_ips = [e.get("src_ip") for e in connects if e.get("src_ip")]
    unique_ips = set(all_ips)

    # Filter private IPs for real attacker count
    public_ips = set()
    for ip in unique_ips:
        try:
            if not ipaddress.ip_address(ip).is_private:
                public_ips.add(ip)
        except ValueError:
            pass

    # Top credentials
    creds_ok   = Counter((e.get("username",""), e.get("password","")) for e in logins_ok)
    creds_fail = Counter((e.get("username",""), e.get("password","")) for e in logins_fail)

    # Top commands
    cmd_counter = Counter(e.get("input","").strip() for e in commands if e.get("input","").strip())

    # Connections per hour (UTC)
    hourly = Counter()
    for e in connects:
        ts = e.get("timestamp","")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
                hourly[dt.strftime("%Y-%m-%d %H:00")] += 1
            except ValueError:
                pass

    # Connections per day
    daily = Counter()
    for e in connects:
        ts = e.get("timestamp","")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
                daily[dt.strftime("%Y-%m-%d")] += 1
            except ValueError:
                pass

    # Top attacker IPs
    ip_counter = Counter(all_ips)

    # Client versions (SSH banners)
    versions = [e for e in events if e.get("eventid") == "cowrie.client.version"]
    version_counter = Counter(e.get("version","unknown") for e in versions)

    # Session duration
    closed = [e for e in events if e.get("eventid") == "cowrie.session.closed"]
    durations = []
    for e in closed:
      d = e.get("duration")
      if d is not None:
        try:
            durations.append(float(d))
        except (ValueError, TypeError):
            pass
    avg_duration = sum(durations) / len(durations) if durations else 0

    return {
        "summary": {
            "total_events":     len(events),
            "total_connections":len(connects),
            "unique_ips":       len(unique_ips),
            "public_ips":       len(public_ips),
            "logins_success":   len(logins_ok),
            "logins_failed":    len(logins_fail),
            "commands_run":     len(commands),
            "downloads":        len(downloads),
            "avg_session_sec":  round(avg_duration, 2),
        },
        "top_creds_ok":      creds_ok.most_common(20),
        "top_creds_fail":    creds_fail.most_common(20),
        "top_commands":      cmd_counter.most_common(25),
        "top_ips":           ip_counter.most_common(20),
        "hourly":            sorted(hourly.items()),
        "daily":             sorted(daily.items()),
        "top_versions":      version_counter.most_common(10),
    }

# ── Dashboard HTML ─────────────────────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Honeypot Analytics Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg:       #0a0e1a;
    --surface:  #111827;
    --card:     #1a2235;
    --border:   #1f2e47;
    --accent:   #00d4ff;
    --accent2:  #ff4444;
    --accent3:  #ffd700;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --green:    #00ff88;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    min-height: 100vh;
  }
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 1.5rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  header .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent2);
    box-shadow: 0 0 8px var(--accent2);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  header h1 { font-size: 1.4rem; font-weight: 600; color: var(--text); }
  header .badge {
    margin-left: auto;
    font-size: .75rem;
    background: rgba(0,212,255,.1);
    border: 1px solid var(--accent);
    color: var(--accent);
    padding: .25rem .75rem;
    border-radius: 999px;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }

  /* Summary cards */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
  }
  .stat-card .value {
    font-size: 2rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    line-height: 1;
    margin-bottom: .4rem;
  }
  .stat-card .label { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .stat-card.red   .value { color: var(--accent2); }
  .stat-card.blue  .value { color: var(--accent);  }
  .stat-card.gold  .value { color: var(--accent3); }
  .stat-card.green .value { color: var(--green);   }

  /* Charts grid */
  .charts-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .charts-grid.full { grid-template-columns: 1fr; }
  .chart-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
  }
  .chart-card h2 {
    font-size: .85rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin-bottom: 1.25rem;
  }
  .chart-card canvas { max-height: 280px; }

  /* Tables */
  .tables-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .table-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    overflow: hidden;
  }
  .table-card h2 {
    font-size: .85rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin-bottom: 1rem;
  }
  table { width: 100%; border-collapse: collapse; font-size: .83rem; }
  th { color: var(--muted); font-weight: 500; text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--border); }
  td { padding: .45rem .6rem; border-bottom: 1px solid rgba(31,46,71,.5); font-family: monospace; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(0,212,255,.03); }
  .rank { color: var(--muted); font-size: .75rem; }
  .bar-cell { display: flex; align-items: center; gap: .5rem; }
  .bar { height: 6px; border-radius: 3px; background: var(--accent); opacity: .7; min-width: 2px; }
  .bar.red  { background: var(--accent2); }
  .bar.gold { background: var(--accent3); }
  .count { color: var(--accent); font-weight: 600; }

  footer {
    text-align: center;
    padding: 2rem;
    color: var(--muted);
    font-size: .8rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>🍯 Honeypot Analytics Dashboard</h1>
  <span class="badge">Cowrie SSH · sensor: honeypot</span>
</header>

<div class="container">

  <!-- Summary cards -->
  <div class="stats-grid" id="stats"></div>

  <!-- Hourly activity -->
  <div class="charts-grid full">
    <div class="chart-card">
      <h2>📈 Connection Activity Over Time</h2>
      <canvas id="hourlyChart"></canvas>
    </div>
  </div>

  <!-- Commands + Versions -->
  <div class="charts-grid">
    <div class="chart-card">
      <h2>💻 Top Commands Executed</h2>
      <canvas id="cmdChart"></canvas>
    </div>
    <div class="chart-card">
      <h2>🤖 Attacker SSH Client Versions</h2>
      <canvas id="versionChart"></canvas>
    </div>
  </div>

  <!-- Tables -->
  <div class="tables-grid">
    <div class="table-card">
      <h2>🔑 Top Credentials (Successful Logins)</h2>
      <table id="credsTable"></table>
    </div>
    <div class="table-card">
      <h2>🌐 Top Attacker IPs</h2>
      <table id="ipsTable"></table>
    </div>
  </div>

  <div class="tables-grid" style="grid-template-columns:1fr">
    <div class="table-card">
      <h2>⚠️ Top Commands Run by Attackers</h2>
      <table id="cmdsTable"></table>
    </div>
  </div>

</div>

<footer>
  Generated by <strong>analyze.py</strong> · Data from Cowrie SSH Honeypot · 
  <span id="genTime"></span>
</footer>

<script>
const DATA = __DATA__;

// ── Helpers ────────────────────────────────────────────────────────────────
document.getElementById('genTime').textContent = 'Generated ' + new Date().toLocaleString();

function fmt(n) { return n.toLocaleString(); }

const CHART_DEFAULTS = {
  color: '#e2e8f0',
  plugins: { legend: { labels: { color: '#64748b', font: { size: 11 } } } },
};
Chart.defaults.color = '#64748b';

// ── Summary cards ──────────────────────────────────────────────────────────
const s = DATA.summary;
const cards = [
  { label: 'Total Events',     value: fmt(s.total_events),     cls: 'blue'  },
  { label: 'Connections',      value: fmt(s.total_connections), cls: 'blue'  },
  { label: 'Unique IPs',       value: fmt(s.unique_ips),        cls: 'gold'  },
  { label: 'Public Attackers', value: fmt(s.public_ips),        cls: 'red'   },
  { label: 'Logins Success',   value: fmt(s.logins_success),    cls: 'red'   },
  { label: 'Logins Failed',    value: fmt(s.logins_failed),     cls: 'gold'  },
  { label: 'Commands Run',     value: fmt(s.commands_run),      cls: 'red'   },
  { label: 'Avg Session (s)',  value: s.avg_session_sec,        cls: 'green' },
];
const statsEl = document.getElementById('stats');
cards.forEach(c => {
  statsEl.innerHTML += `<div class="stat-card ${c.cls}">
    <div class="value">${c.value}</div>
    <div class="label">${c.label}</div>
  </div>`;
});

// ── Hourly chart ───────────────────────────────────────────────────────────
const hourlyLabels = DATA.hourly.map(([h]) => h.slice(5)); // MM-DD HH:00
const hourlyVals   = DATA.hourly.map(([,v]) => v);

new Chart(document.getElementById('hourlyChart'), {
  type: 'line',
  data: {
    labels: hourlyLabels,
    datasets: [{
      label: 'Connections / hour',
      data: hourlyVals,
      borderColor: '#00d4ff',
      backgroundColor: 'rgba(0,212,255,.08)',
      fill: true,
      tension: 0.3,
      pointRadius: hourlyLabels.length > 100 ? 0 : 2,
      borderWidth: 1.5,
    }]
  },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { maxTicksLimit: 12, color: '#64748b' }, grid: { color: '#1f2e47' } },
      y: { ticks: { color: '#64748b' }, grid: { color: '#1f2e47' } },
    }
  }
});

// ── Top commands bar chart ─────────────────────────────────────────────────
const topCmds = DATA.top_commands.slice(0, 12);
new Chart(document.getElementById('cmdChart'), {
  type: 'bar',
  data: {
    labels: topCmds.map(([cmd]) => cmd.length > 30 ? cmd.slice(0,30)+'…' : cmd),
    datasets: [{
      label: 'Times executed',
      data: topCmds.map(([,v]) => v),
      backgroundColor: 'rgba(255,68,68,.7)',
      borderColor: '#ff4444',
      borderWidth: 1,
      borderRadius: 4,
    }]
  },
  options: {
    indexAxis: 'y',
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#64748b' }, grid: { color: '#1f2e47' } },
      y: { ticks: { color: '#e2e8f0', font: { family: 'monospace', size: 11 } }, grid: { display: false } },
    }
  }
});

// ── SSH versions doughnut ──────────────────────────────────────────────────
const topVers = DATA.top_versions.slice(0, 8);
new Chart(document.getElementById('versionChart'), {
  type: 'doughnut',
  data: {
    labels: topVers.map(([v]) => v.length > 35 ? v.slice(0,35)+'…' : v),
    datasets: [{
      data: topVers.map(([,c]) => c),
      backgroundColor: [
        '#00d4ff','#ff4444','#ffd700','#00ff88',
        '#a78bfa','#fb923c','#34d399','#f472b6'
      ],
      borderWidth: 0,
    }]
  },
  options: {
    responsive: true,
    plugins: {
      legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 12, padding: 8 } }
    }
  }
});

// ── Credentials table ──────────────────────────────────────────────────────
const maxCred = DATA.top_creds_ok[0]?.[1] || 1;
const credsEl = document.getElementById('credsTable');
credsEl.innerHTML = '<tr><th>#</th><th>Username</th><th>Password</th><th>Count</th></tr>';
DATA.top_creds_ok.slice(0,15).forEach(([[u,p], c], i) => {
  const w = Math.round((c/maxCred)*80);
  credsEl.innerHTML += `<tr>
    <td class="rank">${i+1}</td>
    <td>${u}</td>
    <td>${p}</td>
    <td><div class="bar-cell"><div class="bar gold" style="width:${w}px"></div><span class="count">${c}</span></div></td>
  </tr>`;
});

// ── IPs table ──────────────────────────────────────────────────────────────
const maxIP = DATA.top_ips[0]?.[1] || 1;
const ipsEl = document.getElementById('ipsTable');
ipsEl.innerHTML = '<tr><th>#</th><th>IP Address</th><th>Connections</th></tr>';
DATA.top_ips.slice(0,15).forEach(([ip, c], i) => {
  const w = Math.round((c/maxIP)*80);
  ipsEl.innerHTML += `<tr>
    <td class="rank">${i+1}</td>
    <td>${ip}</td>
    <td><div class="bar-cell"><div class="bar red" style="width:${w}px"></div><span class="count">${c}</span></div></td>
  </tr>`;
});

// ── Commands table ─────────────────────────────────────────────────────────
const maxCmd = DATA.top_commands[0]?.[1] || 1;
const cmdsEl = document.getElementById('cmdsTable');
cmdsEl.innerHTML = '<tr><th>#</th><th>Command</th><th>Count</th></tr>';
DATA.top_commands.slice(0,20).forEach(([cmd, c], i) => {
  const w = Math.round((c/maxCmd)*120);
  cmdsEl.innerHTML += `<tr>
    <td class="rank">${i+1}</td>
    <td>${cmd.replace(/</g,'&lt;')}</td>
    <td><div class="bar-cell"><div class="bar" style="width:${w}px"></div><span class="count">${c}</span></div></td>
  </tr>`;
});
</script>
</body>
</html>
"""

# ── Dashboard generator ────────────────────────────────────────────────────────
def generate_dashboard(data: dict, output_path: str):
    html = HTML_TEMPLATE.replace("__DATA__", json.dumps(data, ensure_ascii=False))
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Dashboard written to: {output_path}")

# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Cowrie Honeypot Log Analyzer")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR, help="Directory containing cowrie.json* files")
    parser.add_argument("--output",  default=DEFAULT_OUTPUT,  help="Output HTML path")
    args = parser.parse_args()

    events = load_logs(args.log_dir)
    data   = analyze(events)

    print("\n── Summary ──────────────────────────────────────")
    for k, v in data["summary"].items():
        print(f"  {k:<22} {v:,}" if isinstance(v, int) else f"  {k:<22} {v}")

    print("\n── Top 5 Credentials ────────────────────────────")
    for (u, p), c in data["top_creds_ok"][:5]:
        print(f"  {u}:{p}  →  {c}x")

    print("\n── Top 5 Commands ───────────────────────────────")
    for cmd, c in data["top_commands"][:5]:
        print(f"  [{c:>5}] {cmd}")

    generate_dashboard(data, args.output)

if __name__ == "__main__":
    main()
