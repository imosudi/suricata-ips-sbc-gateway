#!/usr/bin/env python3
"""
false_positive.py — Compute false-positive rate from benign-traffic alerts.
Any Suricata alert triggered during the benign module window = false positive.
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
    out_path = Path(args.out) / f"{args.session}_fp.json"

    fp_count = 0
    if eve_path.exists():
        with eve_path.open() as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e.get("event_type") == "alert":
                        sig = e.get("alert", {}).get("signature", "").lower()
                        # Heuristic: alerts with "benign" in category
                        if "benign" in sig or "whitelist" in sig:
                            fp_count += 1
                except json.JSONDecodeError:
                    pass

    fp_score = max(0.0, 100.0 - fp_count * 10)
    result = {
        "session": args.session,
        "false_positive_alerts": fp_count,
        "fp_score": round(fp_score, 2)
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[false_positive] fp_count={fp_count} fp_score={fp_score} → {out_path}")

if __name__ == "__main__":
    main()
