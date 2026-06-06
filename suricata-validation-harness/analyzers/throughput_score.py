#!/usr/bin/env python3
"""
throughput_score.py — Estimate throughput score from rx/tx bytes delta.
Placeholder: extend with iperf3 JSON output for accurate measurement.
"""
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    out_path = Path(args.out) / f"{args.session}_throughput.json"
    result = {
        "session": args.session,
        "throughput_score": 100.0,
        "note": "Placeholder — integrate iperf3 JSON for real measurement"
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[throughput_score] throughput_score={result['throughput_score']} → {out_path}")

if __name__ == "__main__":
    main()
