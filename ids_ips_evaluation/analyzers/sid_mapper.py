#!/usr/bin/env python3
"""
sid_mapper.py — Map Suricata SIDs from EVE alerts to harness modules
using rule_mapping.yaml. Produces a per-module SID hit summary.
"""
import argparse, json, yaml
from pathlib import Path
from collections import defaultdict

def in_range(sid: int, ranges: list) -> bool:
    return any(r["start"] <= sid <= r["end"] for r in ranges)

def classify(sig: str, sid: int, modules: dict) -> str:
    sig_lower = sig.lower()
    for name, info in modules.items():
        if sid in info.get("sid_exact", []):
            return name
        if in_range(sid, info.get("sid_ranges", [])):
            return name
        if any(kw in sig_lower for kw in info.get("keywords", [])):
            return name
    return "unknown"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session",  required=True)
    ap.add_argument("--rule-map", required=True)
    args = ap.parse_args()

    log_dir  = Path(__file__).parent.parent / "logs"
    eve_path = log_dir / f"{args.session}_eve.json"
    rule_map = yaml.safe_load(Path(args.rule_map).read_text())["modules"]

    hits: dict[str, list] = defaultdict(list)
    if eve_path.exists():
        with eve_path.open() as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e.get("event_type") == "alert":
                        a   = e["alert"]
                        mod = classify(a.get("signature",""), a.get("signature_id",0), rule_map)
                        hits[mod].append(a.get("signature_id"))
                except (json.JSONDecodeError, KeyError):
                    pass

    print(f"[sid_mapper] Session: {args.session}")
    for mod, sids in sorted(hits.items()):
        print(f"  {mod:15s}: {len(sids):4d} alerts  SIDs={sorted(set(sids))[:5]}...")

if __name__ == "__main__":
    main()
