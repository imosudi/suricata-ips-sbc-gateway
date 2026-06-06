
#!/usr/bin/env bash
# =============================================================================
# Suricata Rule Engine Setup Script (Modular)
# Inline IPS (NFQUEUE) — SBC Gateway
# FH Technikum Wien — IT Security Lab 2026
#
# What this script does:
#   1. Creates modular rule directory structure
#   2. Installs optimised detection rule sets
#   3. Enables/disables rule groups via symlinks
#   4. Builds unified local.rules (auto-aggregation)
#   5. Validates Suricata configuration
#   6. Reloads Suricata safely (no downtime)
#
# Usage:
#   chmod +x rules_setup.sh
#   sudo ./rules_setup.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── CONFIG ────────────────────────────────────────────────────────────────────
RULES_BASE="/etc/suricata/rules"
AVAILABLE="${RULES_BASE}/available"
ENABLED="${RULES_BASE}/enabled"
LOCAL_RULES="${RULES_BASE}/local.rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"

# ── LOGGING ───────────────────────────────────────────────────────────────────
log() { echo -e "[+] $1"; }
warn() { echo -e "[!] $1"; }
err() { echo -e "[✗] $1" >&2; exit 1; }

# ── PRECHECK ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Run as root"

# ── STEP 1: DIRECTORY STRUCTURE ───────────────────────────────────────────────
log "Creating rule directories..."
mkdir -p "$AVAILABLE" "$ENABLED"
chmod 755 "$RULES_BASE" "$AVAILABLE" "$ENABLED"

# ── STEP 2: WRITE RULE FILES ──────────────────────────────────────────────────
log "Deploying rule modules..."

# ── TRUSTED DEVICE BYPASS ─────────────────────────────────────────────────────
cat > "${AVAILABLE}/10_trusted.rules" << EOF
# =============================================================================
# Trusted Device Bypass Rule
# Prevents IPS from blocking trusted administrative device
# =============================================================================

pass ethernet any any -> any any (msg:"TRUSTED DEVICE BYPASS"; ether src ${trusted_mac}; sid:9000000; rev:1;)

EOF

# ICMP
cat > "${AVAILABLE}/20_icmp.rules" << 'EOF'
alert icmp any any -> $HOME_NET any (msg:"ICMP Timestamp Request"; itype:13; sid:9000001; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Timestamp Reply"; itype:14; sid:9000002; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood Detected"; itype:8; threshold:type both, track by_src, count 50, seconds 5; sid:9000010; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Redirect Message"; itype:5; sid:9000011; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Router Advertisement"; itype:9; sid:9000012; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Fragmentation Needed"; itype:3; icode:4; sid:9000013; rev:1;)
EOF

# HTTP
cat > "${AVAILABLE}/30_http.rules" << 'EOF'
alert http any any -> $HOME_NET any (msg:"HTTP Big Bang Theory Detected"; content:"Big Bang Theory"; http_uri; sid:9000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP SQL Injection Attempt"; http.uri; content:"' OR '1'='1"; nocase; sid:9000020; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP UNION SELECT Injection"; http.uri; content:"UNION SELECT"; nocase; sid:9000021; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP Directory Traversal"; http.uri; content:"../"; sid:9000022; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP Nikto Scanner Detected"; http.user_agent; content:"Nikto"; nocase; sid:9000023; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP sqlmap Scanner Detected"; http.user_agent; content:"sqlmap"; nocase; sid:9000024; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP curl Scripted Request"; http.user_agent; content:"curl/"; sid:9000025; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP PUT Method Detected"; http.method; content:"PUT"; sid:9000026; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP DELETE Method Detected"; http.method; content:"DELETE"; sid:9000027; rev:1;)
EOF

# TLS
cat > "${AVAILABLE}/40_tls.rules" << 'EOF'
alert tls any any -> any any (msg:"TLS Access example.com"; tls.sni; content:"example.com"; sid:9000004; rev:1;)
alert tls any any -> any any (msg:"TLS Access example.org"; tls.sni; content:"example.org"; sid:9000005; rev:1;)
alert tls any any -> any any (msg:"TLS Access example.net"; tls.sni; content:"example.net"; sid:9000006; rev:1;)
alert tls any any -> any any (msg:"TLS Self-Signed Certificate"; tls.cert_subject; pcre:"/^(CN|O)=/"; tls.cert_issuer; pcre:"/^(CN|O)=/"; sid:9000030; rev:1;)
alert tls any any -> any any (msg:"TLS Expired Certificate"; tls.cert_notafter; content:"1970"; sid:9000031; rev:1;)
alert tls any any -> $HOME_NET any (msg:"TLS Deprecated Version Detected"; tls.version; content:"TLS 1.0"; sid:9000032; rev:1;)
alert tls any any -> $HOME_NET !443 (msg:"TLS on Non-Standard Port"; sid:9000033; rev:1;)
EOF

# TELNET
cat > "${AVAILABLE}/50_telnet.rules" << 'EOF'
alert tcp any any -> $HOME_NET 23 (msg:"Telnet Big Bang Theory"; content:"Big Bang Theory"; sid:9000007; rev:1;)
EOF

# SCAN
cat > "${AVAILABLE}/60_scan.rules" << 'EOF'
alert tcp any any -> $HOME_NET any (msg:"Possible SYN Scan"; flags:S; threshold:type threshold, track by_src, count 10, seconds 2; sid:9000008; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"TCP NULL Scan"; flags:0; sid:9000070; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"TCP FIN Scan"; flags:F; sid:9000071; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"TCP XMAS Scan"; flags:FPU; sid:9000072; rev:1;)
alert udp any any -> $HOME_NET any (msg:"UDP Port Scan"; threshold:type both, track by_src, count 20, seconds 3; sid:9000073; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"TCP ACK Scan"; flags:A!SPRFU; threshold:type both, track by_src, count 10, seconds 2; sid:9000074; rev:1;)
EOF

# DNS
cat > "${AVAILABLE}/70_dns.rules" << 'EOF'
alert dns any any -> any any (msg:"DNS Suspiciously Long Query"; dns.query; pcre:"/.{50,}/"; sid:9000040; rev:1;)
alert dns any any -> any any (msg:"DNS TXT Record Query"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9+\/=]{20,}/"; sid:9000041; rev:1;)
alert dns any any -> any any (msg:"DNS Query for Localhost"; dns.query; content:"localhost"; nocase; sid:9000042; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"DNS High Query Rate"; threshold:type both, track by_src, count 100, seconds 5; sid:9000043; rev:1;)
alert udp any any -> $HOME_NET !53 (msg:"DNS Response on Non-Standard Port"; dns.query; sid:9000044; rev:1;)
EOF

# SSH
cat > "${AVAILABLE}/80_ssh.rules" << 'EOF'
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 30; sid:9000050; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Version Scan"; content:"SSH-"; depth:4; sid:9000051; rev:1;)
alert tcp any any -> $HOME_NET !22 (msg:"SSH on Non-Standard Port"; content:"SSH-"; depth:4; sid:9000052; rev:1;)
EOF

# FTP
cat > "${AVAILABLE}/90_ftp.rules" << 'EOF'
alert tcp any any -> $HOME_NET 21 (msg:"FTP Anonymous Login Attempt"; content:"USER anonymous"; nocase; sid:9000060; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"FTP Plaintext USER Command"; content:"USER "; sid:9000061; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"FTP Plaintext PASS Command"; content:"PASS "; sid:9000062; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"FTP PORT Command — Possible Bounce"; content:"PORT "; sid:9000063; rev:1;)
EOF

# SMTP
cat > "${AVAILABLE}/100_smtp.rules" << 'EOF'
alert tcp any any -> $HOME_NET 25 (msg:"SMTP Open Relay Probe"; content:"RCPT TO:"; nocase; sid:9000080; rev:1;)
alert tcp any any -> $HOME_NET 25 (msg:"SMTP AUTH Brute Force"; content:"AUTH LOGIN"; threshold:type both, track by_src, count 5, seconds 30; sid:9000081; rev:1;)
alert tcp any any -> $HOME_NET 25 (msg:"SMTP EHLO with IP Literal"; content:"EHLO ["; sid:9000082; rev:1;)
EOF

# POLICY
cat > "${AVAILABLE}/110_policy.rules" << 'EOF'
alert tcp any any -> $HOME_NET 23 (msg:"POLICY Telnet Session Initiated"; flow:to_server,established; sid:9000090; rev:1;)
alert http any any -> $HOME_NET any (msg:"POLICY HTTP Unencrypted Login Form"; http.uri; content:"/login"; nocase; sid:9000091; rev:1;)
alert http any any -> $HOME_NET any (msg:"POLICY HTTP Unencrypted Admin Path"; http.uri; content:"/admin"; nocase; sid:9000092; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"POLICY ICMP Large Payload"; dsize:>512; sid:9000093; rev:1;)
alert tcp $HOME_NET any -> any 6667 (msg:"POLICY Outbound IRC Port 6667"; sid:9000094; rev:1;)
alert tcp $HOME_NET any -> any 9001 (msg:"POLICY Possible Tor Relay Connection"; sid:9000095; rev:1;)
alert tcp $HOME_NET any -> any 9050 (msg:"POLICY Possible Tor SOCKS Proxy"; sid:9000096; rev:1;)
EOF

# LOCAL TEST
cat > "${AVAILABLE}/120_local.rules" << 'EOF'
alert icmp any any -> any any (msg:"ICMP Test Rule"; sid:9000099; rev:1;)
alert http any any -> $HOME_NET any (msg:"HTTP Test Rule"; content:"Test"; http_uri; sid:9000098; rev:1;)
alert tcp any any -> $HOME_NET 12345 (msg:"TCP Test Rule"; content:"Test"; sid:9000097; rev:1;)
alert udp any any -> $HOME_NET 54321 (msg:"UDP Test Rule"; content:"Test"; sid:9000096; rev:1;)
alert tls any any -> $HOME_NET any (msg:"TLS Test Rule"; tls.sni; content:"Test"; sid:9000095; rev:1;)
alert dns any any -> $HOME_NET any (msg:"DNS Test Rule"; dns.query; content:"Test"; sid:9000094; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Test Rule"; content:"Test"; sid:9000093; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"FTP Test Rule"; content:"Test"; sid:9000092; rev:1;)
alert tcp any any -> $HOME_NET 25 (msg:"SMTP Test Rule"; content:"Test"; sid:9000091; rev:1;)
alert tcp any any -> $HOME_NET 23 (msg:"Telnet Test Rule"; content:"Test"; sid:9000090; rev:1;)
EOF

# ── STEP 3: ENABLE ALL MODULES ───────────────────────────────────────────────
log "Enabling rule modules..."
rm -f ${ENABLED}/*
for f in ${AVAILABLE}/*.rules; do
    ln -s "$f" "${ENABLED}/$(basename "$f")"
done

# ── STEP 4: BUILD local.rules ────────────────────────────────────────────────
log "Building unified local.rules..."
echo "# Auto-generated — DO NOT EDIT" > "$LOCAL_RULES"
for f in ${ENABLED}/*.rules; do
    cat "$f" >> "$LOCAL_RULES"
    echo "" >> "$LOCAL_RULES"
done

chmod 644 "$LOCAL_RULES"

# ── STEP 5: VALIDATE CONFIG ──────────────────────────────────────────────────
log "Validating Suricata configuration..."
suricata -T -c "$SURICATA_YAML" -v || err "Validation failed"

# ── STEP 6: RELOAD SURICATA ──────────────────────────────────────────────────
log "Reloading Suricata rules (zero downtime)..."
kill -USR2 $(cat /run/suricata.pid)

log "Rule engine deployment complete."