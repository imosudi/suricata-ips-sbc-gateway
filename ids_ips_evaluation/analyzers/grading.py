#!/usr/bin/env python3
"""
grading.py — Aggregate dimension scores into a final grade.
Reads individual *_detection.json, *_ips.json, *_latency.json, *_fp.json
and applies weights from scoring.conf.
"""
import argparse, json, configparser
from pathlib import Path

DEFAULTS = {
    "WEIGHT_DETECTION": 35,
    "WEIGHT_IPS_BLOCK": 25,
    "WEIGHT_LATENCY": 20,
    "WEIGHT_FALSE_POSITIVE": 20,
    "GRADE_A": 90, "GRADE_B": 80, "GRADE_C": 70, "GRADE_D": 60,
}

def load_conf(path: Path) -> dict:
    cfg = dict(DEFAULTS)
    if not path.exists():
        return cfg
    raw = path.read_text()
    # Parse KEY=VALUE pairs (ignore comments)
    for line in raw.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            try: cfg[k.strip()] = int(v.strip())
            except ValueError: pass
    return cfg

def letter(score: float, cfg: dict) -> str:
    if score >= cfg["GRADE_A"]: return "A"
    if score >= cfg["GRADE_B"]: return "B"
    if score >= cfg["GRADE_C"]: return "C"
    if score >= cfg["GRADE_D"]: return "D"
    return "F"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session",       required=True)
    ap.add_argument("--scoring-conf",  required=True)
    ap.add_argument("--out",           required=True)
    args = ap.parse_args()

    res_dir = Path(args.out)
    cfg     = load_conf(Path(args.scoring_conf))

    def load(suffix: str, key: str, default: float = 0.0) -> float:
        p = res_dir / f"{args.session}_{suffix}.json"
        if not p.exists(): return default
        return float(json.loads(p.read_text()).get(key, default))

    det_score = load("detection",  "detection_rate")
    ips_score = load("ips",        "block_rate_pct")
    lat_score = load("latency",    "latency_score")
    fp_score  = load("fp",         "fp_score")

    total = (
        det_score * cfg["WEIGHT_DETECTION"]    / 100
      + ips_score * cfg["WEIGHT_IPS_BLOCK"]    / 100
      + lat_score * cfg["WEIGHT_LATENCY"]      / 100
      + fp_score  * cfg["WEIGHT_FALSE_POSITIVE"]/ 100
    )
    grade = letter(total, cfg)

    result = {
        "session": args.session,
        "scores": {
            "detection":      det_score,
            "ips_block":      ips_score,
            "latency":        lat_score,
            "false_positive": fp_score,
        },
        "weights": {
            "detection":      cfg["WEIGHT_DETECTION"],
            "ips_block":      cfg["WEIGHT_IPS_BLOCK"],
            "latency":        cfg["WEIGHT_LATENCY"],
            "false_positive": cfg["WEIGHT_FALSE_POSITIVE"],
        },
        "final_score": round(total, 2),
        "grade": grade,
    }

    out_path = res_dir / f"{args.session}_results.json"
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[grading] Final score={total:.1f} Grade={grade} → {out_path}")

if __name__ == "__main__":
    main()
