# Suricata Validation Harness — Kali Attacker Edition

Automated end-to-end validation suite for a Suricata IDS/IPS deployment,
designed to run on **Kali Linux** as the attacker machine.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                        Lab topology                         │
  │                                                             │
  │  ┌──────────────┐  attacks   ┌──────────────────────────┐  │
  │  │  Kali Linux  │ ─────────► │  Victim hosts            │  │
  │  │ (this tool)  │            │  10.10.10.2 / .3 / .4    │  │
  │  └──────┬───────┘            └──────────────────────────┘  │
  │         │                             ▲  (monitored)        │
  │         │ SSH/SCP (collection)        │                     │
  │         ▼                    ┌────────┴─────────────────┐   │
  │  ┌──────────────┐            │  Suricata gateway        │   │
  │  │  EVE JSON    │ ◄──────── │  10.10.10.1              │   │
  │  │  stats.log   │            │  IDS / IPS mode          │   │
  │  │  pcap-log    │            └──────────────────────────┘   │
  │  └──────────────┘                                           │
  └─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Configure the lab
vi config/lab.conf       # GW_HOST, GW_USER, GW_SSH_KEY, KALI_IFACE
vi config/targets.conf   # PRIMARY_TARGET (victim, not the Suricata IDS/IPS gateway)

# 3. Set up passwordless SSH from Kali to the Suricata IDS/IPS gateway
ssh-copy-id -i ~/.ssh/id_ed25519_lab user@10.10.10.1

# 4. Make scripts executable
chmod +x validation_harness.sh attacks/*.sh collectors/*.sh

# 5. Run full suite (IDS mode, HTML report)
sudo ./validation_harness.sh

# 6. Override Suricata IDS/IPS gateway/target on the fly
sudo ./validation_harness.sh --gw-host 10.10.10.1 --target 10.10.10.2

# 7. Pull & analyse evidence without re-running attacks
./validation_harness.sh --collect-only
```

## Configuration

### `config/lab.conf`

| Key | Description |
|-----|-------------|
| `GW_HOST` | Suricata gateway IP (SSH target for collection) |
| `GW_USER` | SSH user on gateway (needs read access to EVE/stats logs) |
| `GW_SSH_KEY` | Path to SSH private key (passwordless preferred) |
| `GW_EVE_LOG` | Absolute path to `eve.json` on the gateway |
| `GW_STATS_LOG` | Absolute path to `stats.log` on the gateway |
| `KALI_IFACE` | Kali's outbound NIC — used for local PCAP capture |
| `SURICATA_MODE` | `ids` or `ips` — controls whether block-rate is scored |

### `config/targets.conf`

Defines victim hosts — the machines **behind** the Suricata IDS/IPS gateway that receive attack
traffic. `GW_HOST` itself is the collection endpoint, not a victim.

## Attack Modules

| Module | Tools | What triggers Suricata |
|--------|-------|------------------------|
| `icmp` | hping3, ping | ICMP flood, oversized packet, timestamp req |
| `scan` | nmap | SYN/NULL/XMAS/version/OS scans |
| `dns` | dig | NXDOMAIN flood, ANY amplification, DNS tunnel |
| `ssh` | ssh, hydra | Brute force, banner grab, credential stuffing |
| `http` | curl, nikto | SQLi, XSS, path traversal, scanner UA strings |
| `tls` | openssl | Weak ciphers, old protocol versions, cert check |
| `ftp` | ftp, hydra | Anonymous login, credential stuffing |
| `smtp` | nc, swaks | Open relay, VRFY/EXPN user enumeration |
| `policy` | nc, curl | Tor ports, BitTorrent DHT, IRC, HTTP CONNECT |
| `benign` | curl, ping, dig | Legitimate traffic — false-positive baseline |

## Evidence Collection (SSH-based)

All collectors run on Kali and SSH/SCP into the Suricata IDS/IPS gateway:

| Collector | What it pulls |
|-----------|--------------|
| `eve_collector.sh` | Tails `eve.json` from gateway via SSH |
| `stats_collector.sh` | `suricatasc dump-counters` or `stats.log` tail |
| `pcap_collector.sh` | Local tcpdump on Kali NIC + SCP of Suricata pcap-log |
| `performance_collector.sh` | CPU/RAM from both Kali and gateway via SSH |
| `environment_collector.sh` | Tool versions (Kali) + Suricata version/rules (gateway) |

## Scoring Model

| Dimension | Weight | Source data |
|-----------|--------|-------------|
| Detection rate | 35 % | Alerts per module in EVE JSON |
| IPS block rate | 25 % | `action: blocked` in EVE (IPS mode only) |
| Latency impact | 20 % | Gateway CPU under attack vs baseline |
| False positives | 20 % | Alerts during `benign` module window |

**Grade boundaries:** A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60

## Gateway Prerequisites

The Suricata gateway needs:
- Suricata ≥ 7.0 with `eve-log` output enabled in `suricata.yaml`
- SSH access for `GW_USER` with read permission on the log files
  ```bash
  # Minimal: add GW_USER to suricata group or set log ACLs
  sudo usermod -aG suricata suricata-admin
  ```
- Optional: `pcap-log` enabled in `suricata.yaml` for gateway-side PCAPs
- Optional: `suricatasc` accessible by `GW_USER` for live stats

## Kali Prerequisites

```bash
# Core attack tools (most pre-installed on Kali)
sudo apt install -y nmap hping3 hydra swaks tcpdump curl dig netcat-traditional

# Python deps
pip install -r requirements.txt
```

## Directory Layout

```
suricata-validation-harness/
├── validation_harness.sh   Orchestrator (runs on Kali)
├── config/
│   ├── lab.conf            Suricata IDS/IPS Gateway SSH params + Kali interface
│   ├── targets.conf        Victim host IPs
│   ├── scoring.conf        Weight/threshold overrides
│   ├── attack_profiles.yaml  light / full / aggressive
│   └── rule_mapping.yaml   SID ranges → module names
├── attacks/                One script per protocol (all run on Kali)
├── collectors/             SSH/SCP pullers (run on Kali, reach gateway)
├── analyzers/              Python scoring modules (run on Kali)
├── reports/                HTML/CSV report generators
├── logs/                   Per-session harness logs + collected EVE
├── pcaps/                  Local tcpdump PCAPs + fetched gateway PCAPs
├── results/                JSON scores + final reports
└── archive/                Compressed session archives
```
