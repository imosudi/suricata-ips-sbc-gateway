#!/usr/bin/env python3
"""
latency_score.py — Estimate latency/performance impact on the Suricata gateway.
Reads the dual-side performance JSON produced by performance_collector.sh
(which SSHes to the gateway to collect gateway-side CPU/RAM).

Score of 100 = no measurable impact on gateway under attack load.
Score decreases as gateway CPU climbs above a baseline threshold.
"""
import argparse, json
from pathlib import Path

BASELINE_CPU   = 20.0   # expected gateway CPU % at idle
MAX_PENALTY    = 60.0   # CPU % above which score floors at 0
PENALTY_FACTOR = 100.0 / (MAX_PENALTY - BASELINE_CPU)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    log_dir   = Path(__file__).parent.parent / "logs"
    perf_path = log_dir / f"{args.session}_perf.json"
    out_path  = Path(args.out) / f"{args.session}_latency.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    gw_cpu = 0.0
    kali_cpu = 0.0
    note = "gateway metrics unavailable — using default score"

    if perf_path.exists():
        perf = json.loads(perf_path.read_text())
        # New dual-side format from Kali-edition performance_collector
        if "gateway" in perf:
            gw_cpu   = float(perf["gateway"].get("cpu_usage_pct", 0))
            kali_cpu = float(perf["kali"].get("cpu_usage_pct", 0))
            note = f"gateway CPU {gw_cpu:.1f}% | kali CPU {kali_cpu:.1f}%"
        else:
            # Legacy single-host format fallback
            gw_cpu = float(perf.get("cpu_usage_pct", 0))
            note = f"cpu_usage_pct={gw_cpu:.1f}% (legacy format)"

    excess = max(0.0, gw_cpu - BASELINE_CPU)
    score  = max(0.0, 100.0 - excess * PENALTY_FACTOR)

    result = {
        "session":        args.session,
        "gateway_cpu_pct": gw_cpu,
        "kali_cpu_pct":    kali_cpu,
        "latency_score":  round(score, 2),
        "note":           note,
    }
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[latency_score] gateway_cpu={gw_cpu:.1f}%  score={score:.1f} → {out_path}")

if __name__ == "__main__":
    main()
