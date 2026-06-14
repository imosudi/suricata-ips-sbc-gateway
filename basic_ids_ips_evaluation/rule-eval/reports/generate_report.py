#!/usr/bin/env python3
"""
reports/generate_report.py
Generates an HTML evaluation report from run_<id>.json + collected alert files.
Usage:
  python3 generate_report.py \
      --results  results/run_<id>.json \
      --alerts-dir results/ \
      --run-id    <id> \
      --output    reports/report_<id>.html
"""
import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path

# ── SID → description map ─────────────────────────────────────────────────────
SID_MAP = {
    9000201: "ICMP Timestamp Request",
    9000202: "ICMP Timestamp Reply",
    9000203: "ICMP Flood (threshold)",
    9000300: "HTTP Host: example.com",
    9000301: "HTTP Host: example.net",
    9000302: "HTTP Host: example.org",
    9000303: "HTTP Big Bang Theory — URI",
    9000304: "HTTP Big Bang Theory — Request Body",
    9000305: "HTTP Big Bang Theory — Request Header",
    9000306: "HTTP Big Bang Theory — Response Body",
    9000310: "HTTP SQL Injection in URI",
    9000311: "HTTP Directory Traversal",
    9000312: "HTTP sqlmap Scanner UA",
    9000313: "HTTP Nikto Scanner UA",
    9000401: "TLS SNI example.com",
    9000402: "TLS SNI example.org",
    9000403: "TLS SNI example.net",
    9000404: "TLS Cert CN example.com",
    9000405: "TLS Cert CN example.org",
    9000406: "TLS Cert CN example.net",
    9000410: "TLS 1.0 Deprecated Version",
    9000411: "TLS on Non-Standard Port",
    9000500: "Telnet Big Bang Theory",
    9000501: "Telnet Session Initiated",
    9000502: "Telnet Login Prompt",
    9000503: "Telnet Password Field",
}

MODULE_LABELS = {
    "20": "20_icmp.rules — ICMP Detection",
    "30": "30_http.rules — HTTP Detection",
    "40": "40_tls.rules — TLS/SNI Detection",
    "50": "50_telnet.rules — Telnet Detection",
}

CSS = """
body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
h1   { color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 10px; }
h2   { color: #79c0ff; margin-top: 30px; }
h3   { color: #d2a8ff; }
.meta { color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; }
th   { background: #161b22; color: #58a6ff; padding: 8px 12px; text-align: left; border: 1px solid #30363d; }
td   { padding: 7px 12px; border: 1px solid #21262d; font-size: 0.9em; }
tr:nth-child(even) { background: #161b22; }
.pass  { color: #3fb950; font-weight: bold; }
.fail  { color: #f85149; font-weight: bold; }
.warn  { color: #d29922; font-weight: bold; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
.badge-pass { background: #1a4a1a; color: #3fb950; border: 1px solid #3fb950; }
.badge-fail { background: #4a1a1a; color: #f85149; border: 1px solid #f85149; }
.summary-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; margin: 15px 0; display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; }
.stat { text-align: center; }
.stat-num  { font-size: 2em; font-weight: bold; }
.stat-label { font-size: 0.85em; color: #8b949e; }
pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: 0.8em; overflow-x: auto; color: #a8d8a8; max-height: 300px; }
"""


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []


def load_text(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def extract_fired_sids(alerts_dir, run_id):
    """Parse fast.log snippets to find which SIDs actually fired."""
    fired = set()
    pattern = re.compile(r'\[(\d+):\d+\]')  # [gid:sid]
    for fname in Path(alerts_dir).glob(f"{run_id}_fast_*.txt"):
        text = load_text(fname)
        # fast.log format: [**] [1:9000201:1] ICMP Timestamp ...
        for match in re.finditer(r'\[1:(\d+):\d+\]', text):
            fired.add(int(match.group(1)))
    for fname in Path(alerts_dir).glob(f"{run_id}_eve_*.json"):
        for line in load_text(fname).splitlines():
            try:
                e = json.loads(line)
                sid = e.get("alert", {}).get("signature_id")
                if sid:
                    fired.add(sid)
            except Exception:
                pass
    return fired


def group_by_module(results):
    modules = {}
    for r in results:
        mod = r.get("module", "unknown")
        modules.setdefault(mod, []).append(r)
    return modules


def render_html(run_id, results, fired_sids, alerts_dir):
    total   = len(results)
    passes  = sum(1 for r in results if r["status"] == "pass")
    fails   = total - passes
    pct     = int(100 * passes / total) if total else 0

    # Augment results with SID-based fired check
    augmented = []
    for sid, desc in SID_MAP.items():
        module_prefix = str(sid)[4:6] if len(str(sid)) >= 6 else "??"
        module_key    = str(sid)[:2]
        fired = sid in fired_sids
        augmented.append({
            "sid": sid,
            "module": module_key,
            "description": desc,
            "fired": fired,
        })

    modules = {}
    for item in augmented:
        modules.setdefault(item["module"], []).append(item)

    # Fast log text per module
    fast_texts = {}
    for tag in ["20_icmp", "30_http", "40_tls", "50_telnet"]:
        path = Path(alerts_dir) / f"{run_id}_fast_{tag}.txt"
        fast_texts[tag] = load_text(path)

    fired_count = len(fired_sids)

    html = [f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<title>Suricata Eval Report — {run_id}</title>
<style>{CSS}</style>
</head>
<body>
<h1>🔍 Suricata Rule Evaluation Report</h1>
<div class="meta">
  Run ID: <strong>{run_id}</strong> &nbsp;|&nbsp;
  Generated: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong>
</div>

<div class="summary-box">
  <div class="stat"><div class="stat-num" style="color:#58a6ff">{len(SID_MAP)}</div><div class="stat-label">Rules Under Test</div></div>
  <div class="stat"><div class="stat-num" style="color:#3fb950">{fired_count}</div><div class="stat-label">SIDs Fired</div></div>
  <div class="stat"><div class="stat-num" style="color:#f85149">{len(SID_MAP)-fired_count}</div><div class="stat-label">SIDs Silent</div></div>
  <div class="stat"><div class="stat-num" style="color:#d29922">{pct}%</div><div class="stat-label">Script Pass Rate</div></div>
</div>
"""]

    for mod_key, label in MODULE_LABELS.items():
        items   = modules.get(mod_key, [])
        tag_map = {"20": "20_icmp", "30": "30_http", "40": "40_tls", "50": "50_telnet"}
        tag     = tag_map.get(mod_key, "")
        fast    = fast_texts.get(tag, "")

        html.append(f"<h2>Module {label}</h2>")
        html.append("<table><thead><tr><th>SID</th><th>Description</th><th>Alert Fired</th></tr></thead><tbody>")

        for item in items:
            badge = '<span class="badge badge-pass">FIRED</span>' if item["fired"] \
                    else '<span class="badge badge-fail">SILENT</span>'
            html.append(f"<tr><td>{item['sid']}</td><td>{item['description']}</td><td>{badge}</td></tr>")

        html.append("</tbody></table>")

        if fast:
            html.append(f"<h3>Gateway fast.log (module {mod_key})</h3>")
            html.append(f"<pre>{fast[:4000]}</pre>")
        else:
            html.append("<p style='color:#8b949e;font-size:0.85em'>No fast.log data collected for this module.</p>")

    html.append("</body></html>")
    return "\n".join(html)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results",    required=True)
    parser.add_argument("--alerts-dir", required=True)
    parser.add_argument("--run-id",     required=True)
    parser.add_argument("--output",     required=True)
    args = parser.parse_args()

    results    = load_json(args.results)
    fired_sids = extract_fired_sids(args.alerts_dir, args.run_id)

    print(f"[report] {len(fired_sids)} SID(s) confirmed fired from alert logs")

    html = render_html(args.run_id, results, fired_sids, args.alerts_dir)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)

    print(f"[report] HTML report → {args.output}")


if __name__ == "__main__":
    main()
