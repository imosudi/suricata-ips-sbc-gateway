# Suricata Rule Evaluation Harness

Automated evaluation of Suricata custom rule modules **20, 30, 40, 50** from a
Kali Linux client within the protected LAN (`10.10.10.0/24`).

---

## Topology

```
Kali (this machine)          Gateway (Orange Pi)          External
10.10.10.x  ──── eth0 ────▶  10.10.10.1 / wlan0 ────▶   93.184.216.34
                              Suricata inline (NFQUEUE)    (example.com)
                Target: 10.10.10.150
```

---

## Directory Layout

```
suricata-eval/
├── run_eval.sh            ← main orchestrator (entry point)
├── config/
│   └── eval.conf          ← IPs, SSH key, SIDs, timing — EDIT THIS FIRST
├── attacks/               ← one script per test scenario
│   ├── 20_icmp_timestamp.sh
│   ├── 20_icmp_flood.sh
│   ├── 30_http_example_host.sh
│   ├── 30_http_bigbang.sh
│   ├── 30_http_sqli.sh
│   ├── 30_http_traversal.sh
│   ├── 30_http_scanners.sh
│   ├── 40_tls_sni.sh
│   ├── 40_tls_deprecated.sh
│   ├── 50_telnet_bigbang.sh
│   └── 50_telnet_session.sh
├── analysers/
│   └── analyse_pcaps.sh   ← tshark post-processor for all PCAPs
├── collectors/
│   └── collect_eve.sh     ← SSH pulls eve.json + fast.log from gateway
├── logs/                  ← run_<id>.log  (auto-created)
├── pcaps/                 ← run_<id>_<tag>.pcap  (auto-created)
├── results/               ← run_<id>.json + alert text (auto-created)
├── reports/
│   └── generate_report.py ← HTML report generator
└── archive/
    └── archive_run.sh     ← bundles completed run into .tar.gz
```

---

## Quick Start

### 1. Prerequisites (Kali)

```bash
sudo apt-get install -y nmap hping3 curl ncat tshark tcpdump openssh-client jq python3
```

### 2. Configure

```bash
vim config/eval.conf        # set GATEWAY_IP, TARGET_IP, GW_SSH_KEY, etc.
```

Generate a dedicated SSH key for the gateway collector if needed:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_eval -N ""
ssh-copy-id -i ~/.ssh/id_ed25519_eval.pub mio@10.10.10.1
```

Grant passwordless sudo for log reading on the gateway:

```
# /etc/sudoers.d/suricata-eval  (on gateway)
mio ALL=(ALL) NOPASSWD: /usr/bin/cat /var/log/suricata/*, /usr/bin/tail /var/log/suricata/*, /usr/bin/grep * /var/log/suricata/*
```

### 3. Make all scripts executable

```bash
chmod +x run_eval.sh archive/archive_run.sh \
    attacks/*.sh analysers/*.sh collectors/*.sh
```

### 4. Run

```bash
sudo ./run_eval.sh          # sudo needed for tcpdump + raw socket attacks
```

### 5. Review outputs

| Output | Location |
|--------|----------|
| Full log | `logs/run_<id>.log` |
| JSON results | `results/run_<id>.json` |
| Gateway alerts | `results/run_<id>_fast_*.txt` |
| PCAP files | `pcaps/run_<id>_*.pcap` |
| PCAP analysis | `results/run_<id>_pcap_analysis.txt` |
| HTML report | `reports/report_<id>.html` |
| Archive bundle | `archive/run_<id>.tar.gz` |

---

## Rules Under Test

| Module | SID range | Scenarios |
|--------|-----------|-----------|
| `20_icmp.rules` | 9000201–9000203 | Timestamp Req/Reply, ICMP flood |
| `30_http.rules` | 9000300–9000313 | example.{com,net,org}, Big Bang Theory (URI/body/header/response), SQLi, traversal, sqlmap/Nikto UA |
| `40_tls.rules`  | 9000401–9000411 | SNI detection, cert CN, TLS 1.0, non-standard port |
| `50_telnet.rules`| 9000500–9000503 | Big Bang Theory string, session, login, password prompts |

---

## Important Notes

- **LAN-side blind spot**: Traffic between two LAN hosts (`10.10.10.x → 10.10.10.y`)
  bypasses the gateway entirely (Layer 2 ARP path). Rules only fire for traffic
  that crosses the Orange Pi's `eth0` interface. Attacks targeting `EXTERNAL_IP`
  via the gateway are the most reliable test path for rules 30 and 40.

- **TLS 1.0 tests**: Many servers no longer support TLS 1.0; the attack script
  uses `openssl s_client -tls1` directly against `EXTERNAL_IP`.

- **Telnet port 23**: The fake server listener requires `CAP_NET_BIND_SERVICE`
  or root for ports < 1024. The script uses `sudo ncat -l 23`.

- **IPS vs IDS mode**: In IPS (drop) mode, some attacks will be blocked before
  completion — the PCAP will show a RST or incomplete handshake. This is expected
  and still counts as a rule fire.
