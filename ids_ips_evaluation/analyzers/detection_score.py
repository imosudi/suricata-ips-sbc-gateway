#!/usr/bin/env python3
"""
detection_score.py — Compute per-module detection rate from EVE JSON.
Reads: logs/<session>_eve.json
Writes: results/<session>_detection.json
"""
import argparse, json, sys
from pathlib import Path
from collections import defaultdict

MODULES = ["icmp","scan","dns","ssh","http","tls","ftp","smtp","policy","benign"]

def load_eve(path: Path) -> list[dict]:
    events = []
    with path.open() as f:
        for line in f:
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
    return events

def score(eve_path: Path, rule_map_path: Path | None = None) -> dict:
    events = load_eve(eve_path)
    alerts = [e for e in events if e.get("event_type") == "alert"]
    per_module: dict[str, int] = defaultdict(int)

    for alert in alerts:
        sig = alert.get("alert", {}).get("signature", "").lower()
        sid = alert.get("alert", {}).get("signature_id", 0)
        for mod in MODULES:
            if mod in sig or (9000001 + MODULES.index(mod) * 1000 <= sid
                               < 9000001 + (MODULES.index(mod)+1) * 1000):
                per_module[mod] += 1
                break

    total = len(alerts)
    result = {
        "total_alerts": total,
        "per_module": dict(per_module),
        "detection_rate": round(
            sum(1 for m in MODULES[:-1] if per_module.get(m,0)>0)
            / max(len(MODULES)-1, 1) * 100, 2
        )
    }
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    log_dir     = Path(__file__).parent.parent / "logs"
    eve_path    = log_dir / f"{args.session}_eve.json"
    out_path    = Path(args.out) / f"{args.session}_detection.json"

    if not eve_path.exists():
        print(f"[detection_score] EVE file not found: {eve_path}", file=sys.stderr)
        result = {"total_alerts": 0, "per_module": {}, "detection_rate": 0.0}
    else:
        result = score(eve_path)

    result["session"] = args.session
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[detection_score] detection_rate={result['detection_rate']}% → {out_path}")

if __name__ == "__main__":
    main()
