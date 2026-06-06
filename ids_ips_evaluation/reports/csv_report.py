#!/usr/bin/env python3
"""
csv_report.py — Export results to CSV for spreadsheet analysis.
"""
import argparse, json, csv
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",  required=True)
    ap.add_argument("--out",    required=True)
    args = ap.parse_args()

    data     = json.loads(Path(args.input).read_text())
    session  = data.get("session","report")
    out_path = Path(args.out) / f"{session}_report.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["session","dimension","score","weight"])
        scores  = data.get("scores",{})
        weights = data.get("weights",{})
        for dim, val in scores.items():
            w.writerow([session, dim, val, weights.get(dim,"")])
        w.writerow([session, "FINAL", data.get("final_score",""), ""])
        w.writerow([session, "GRADE", data.get("grade",""), ""])

    print(f"[csv_report] Written → {out_path}")

if __name__ == "__main__":
    main()
