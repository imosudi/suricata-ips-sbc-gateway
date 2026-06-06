#!/usr/bin/env bash
# attacks/scan.sh — Network scanning module
set -euo pipefail

TARGET="${TARGET:-10.10.10.1}"

echo "[scan] Starting scan module → $TARGET"

command -v nmap >/dev/null 2>&1 || { echo "[scan] nmap not found — skipping"; exit 0; }

echo "[scan] SYN scan (top 100 ports)..."
nmap -sS -T4 --top-ports 100 "$TARGET" -oN /dev/null 2>/dev/null || true

echo "[scan] NULL scan..."
nmap -sN -T4 -p 22,80,443 "$TARGET" -oN /dev/null 2>/dev/null || true

echo "[scan] XMAS scan..."
nmap -sX -T4 -p 22,80,443 "$TARGET" -oN /dev/null 2>/dev/null || true

echo "[scan] Version/OS detection..."
nmap -sV -O -T4 --top-ports 20 "$TARGET" -oN /dev/null 2>/dev/null || true

echo "[scan] Module complete."
