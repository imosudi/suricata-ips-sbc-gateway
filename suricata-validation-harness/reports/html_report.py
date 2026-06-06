#!/usr/bin/env python3
"""
html_report.py — Render Jinja2 HTML report from results JSON.
"""
import argparse, json
from pathlib import Path
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

TEMPLATE_DIR = Path(__file__).parent / "templates"

def render_fallback(data: dict, out_path: Path):
    """Minimal HTML without Jinja2."""
    grade = data.get("grade","?")
    score = data.get("final_score",0)
    scores = data.get("scores",{})
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Suricata Validation Report</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:2em auto}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:.5em}}
th{{background:#2c3e50;color:#fff}}
.grade{{font-size:4em;text-align:center;color:#27ae60}}</style></head>
<body><h1>Suricata Validation Report</h1>
<p>Session: {data.get("session","")} &nbsp;|&nbsp; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</p>
<div class="grade">{grade} ({score:.1f}/100)</div>
<h2>Dimension Scores</h2><table>
<tr><th>Dimension</th><th>Score</th><th>Weight</th></tr>"""
    weights = data.get("weights",{})
    for dim,val in scores.items():
        html += f"<tr><td>{dim}</td><td>{val:.1f}</td><td>{weights.get(dim,'-')} %</td></tr>"
    html += "</table></body></html>"
    out_path.write_text(html)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",  required=True)
    ap.add_argument("--out",    required=True)
    args = ap.parse_args()

    data     = json.loads(Path(args.input).read_text())
    session  = data.get("session","report")
    out_path = Path(args.out) / f"{session}_report.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if HAS_JINJA and (TEMPLATE_DIR / "report_template.html").exists():
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        tmpl = env.get_template("report_template.html")
        out_path.write_text(tmpl.render(data=data, now=datetime.utcnow()))
    else:
        render_fallback(data, out_path)

    print(f"[html_report] Written → {out_path}")

if __name__ == "__main__":
    main()
