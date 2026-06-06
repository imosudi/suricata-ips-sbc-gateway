#!/usr/bin/env python3
"""
ips_score.py — Compute block rate from EVE drop events (IPS mode).
Only meaningful when Suricata runs in IPS (inline) mode with drop rules.
"""
import argparse, json, sys
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    log_dir  = Path(__file__).parent.parent / "logs"
    eve_path = log_dir / f"{args.session}_eve.json"
    out_path = Path(args.out) / f"{args.session}_ips.json"

    alerts = drops = 0
    if eve_path.exists():
        with eve_path.open() as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e.get("event_type") == "alert":
                        alerts += 1
                        if e.get("alert", {}).get("action") == "blocked":
                            drops += 1
                except json.JSONDecodeError:
                    pass

    block_rate = round(drops / max(alerts, 1) * 100, 2)
    result = {
        "session": args.session,
        "total_alerts": alerts,
        "blocked": drops,
        "block_rate_pct": block_rate
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[ips_score] block_rate={block_rate}% ({drops}/{alerts}) → {out_path}")

if __name__ == "__main__":
    main()
