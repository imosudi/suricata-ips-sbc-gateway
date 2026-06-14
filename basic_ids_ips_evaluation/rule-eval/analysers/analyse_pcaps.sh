#!/usr/bin/env bash
# analysers/analyse_pcaps.sh
# Post-processes all PCAPs from a run using tshark and emits a summary
# Usage: analyse_pcaps.sh <pcaps_dir> <run_id> <results_dir>
# =============================================================================
PCAPS_DIR="${1:?PCAPS_DIR required}"
RUN_ID="${2:?RUN_ID required}"
RESULTS_DIR="${3:?RESULTS_DIR required}"

OUT="${RESULTS_DIR}/${RUN_ID}_pcap_analysis.txt"
echo "PCAP Analysis — Run ${RUN_ID}" > "${OUT}"
echo "Generated: $(date -Iseconds)"  >> "${OUT}"
echo "==========================================" >> "${OUT}"

analyse_pcap() {
    local pcap="$1"
    local label
    label="$(basename "${pcap}" .pcap)"
    echo "" >> "${OUT}"
    echo "── ${label} ──────────────────────────────" >> "${OUT}"

    if [[ ! -f "${pcap}" ]]; then
        echo "  [NOT FOUND]" >> "${OUT}"
        return
    fi

    local pkt_count
    pkt_count=$(tshark -r "${pcap}" 2>/dev/null | wc -l)
    echo "  Packets captured : ${pkt_count}" >> "${OUT}"

    # Protocol breakdown
    echo "  Protocol summary :" >> "${OUT}"
    tshark -r "${pcap}" -q -z io,phs 2>/dev/null | \
        grep -E "^(icmp|tcp|udp|tls|http)" | \
        awk '{printf "    %-12s frames=%s bytes=%s\n", $1, $2, $3}' >> "${OUT}" || true

    # ICMP-specific
    if echo "${label}" | grep -q "icmp"; then
        echo "  ICMP types seen  :" >> "${OUT}"
        tshark -r "${pcap}" -Y "icmp" -T fields \
               -e icmp.type -e icmp.code 2>/dev/null | \
               sort | uniq -c | \
               awk '{printf "    count=%-4s type=%-4s code=%s\n", $1, $2, $3}' >> "${OUT}" || true
    fi

    # HTTP-specific
    if echo "${label}" | grep -q "http"; then
        echo "  HTTP requests    :" >> "${OUT}"
        tshark -r "${pcap}" -Y "http.request" -T fields \
               -e http.request.method -e http.request.uri \
               -e http.user_agent 2>/dev/null | \
               head -20 >> "${OUT}" || true
    fi

    # TLS-specific: SNI extraction
    if echo "${label}" | grep -q "tls"; then
        echo "  TLS SNI values   :" >> "${OUT}"
        tshark -r "${pcap}" -Y "tls.handshake.extensions_server_name" \
               -T fields -e tls.handshake.extensions_server_name 2>/dev/null | \
               sort -u >> "${OUT}" || true
        echo "  TLS versions     :" >> "${OUT}"
        tshark -r "${pcap}" -Y "tls.record.version" \
               -T fields -e tls.record.version 2>/dev/null | \
               sort | uniq -c >> "${OUT}" || true
    fi

    # TCP ports
    echo "  Top dst ports    :" >> "${OUT}"
    tshark -r "${pcap}" -T fields -e tcp.dstport 2>/dev/null | \
        sort | uniq -c | sort -rn | head -5 | \
        awk '{printf "    port=%-6s count=%s\n", $2, $1}' >> "${OUT}" || true
}

# Analyse each PCAP from this run
for pcap in "${PCAPS_DIR}/${RUN_ID}"_*.pcap; do
    analyse_pcap "${pcap}"
done

echo "" >> "${OUT}"
echo "==========================================" >> "${OUT}"
echo "Analysis complete." >> "${OUT}"

cat "${OUT}"
