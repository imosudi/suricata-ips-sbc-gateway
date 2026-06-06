#!/usr/bin/env python3
"""
report_generator.py — Master report dispatcher.
Reads results JSON and triggers both HTML and CSV generation.
"""
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    results_path = Path(args.out) / f"{args.session}_results.json"
    if not results_path.exists():
        print(f"[report_generator] Results file not found: {results_path}")
        return

    data = json.loads(results_path.read_text())
    grade = data.get("grade", "?")
    score = data.get("final_score", 0)
    print(f"[report_generator] Session {args.session} | Score={score} | Grade={grade}")
    print(f"[report_generator] Run html_report.py / csv_report.py for detailed output.")

if __name__ == "__main__":
    main()
