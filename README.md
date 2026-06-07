<p align="center">
  <img src="images/icon.png" alt="Suricata IPS SBC Gateway icon" width="120" height="120">
</p>

<h1 align="center">Suricata IPS SBC Gateway</h1>

<p align="center">
  Inline IDS/IPS gateway for Raspberry Pi, Orange Pi, and other Debian-based
  single board computers, powered by Suricata in NFQUEUE mode.
</p>

<p align="center">
  <img alt="Raspberry Pi" src="https://img.shields.io/badge/raspberry--pi-C51A4A?style=flat-square&logo=raspberrypi&logoColor=white">
  <img alt="Orange Pi 5" src="https://img.shields.io/badge/orange--pi--5-FF7A00?style=flat-square">
  <img alt="Single Board Computer" src="https://img.shields.io/badge/single--board--computer-455A64?style=flat-square">
  <img alt="Linux Networking" src="https://img.shields.io/badge/linux--networking-FCC624?style=flat-square&logo=linux&logoColor=black">
</p>

<p align="center">
  <img alt="Suricata" src="https://img.shields.io/badge/suricata-IDS%2FIPS-EF3B2D?style=flat-square">
  <img alt="Intrusion Detection" src="https://img.shields.io/badge/intrusion--detection-1565C0?style=flat-square">
  <img alt="Intrusion Prevention" src="https://img.shields.io/badge/intrusion--prevention-2E7D32?style=flat-square">
  <img alt="Inline IPS" src="https://img.shields.io/badge/inline--ips-00897B?style=flat-square">
  <img alt="Deep Packet Inspection" src="https://img.shields.io/badge/deep--packet--inspection-6A1B9A?style=flat-square">
  <img alt="Packet Inspection" src="https://img.shields.io/badge/packet--inspection-512DA8?style=flat-square">
</p>

<p align="center">
  <img alt="iptables" src="https://img.shields.io/badge/iptables-263238?style=flat-square">
  <img alt="nftables" src="https://img.shields.io/badge/nftables-37474F?style=flat-square">
  <img alt="netfilter" src="https://img.shields.io/badge/netfilter-546E7A?style=flat-square">
  <img alt="NFQUEUE" src="https://img.shields.io/badge/nfqueue-00695C?style=flat-square">
  <img alt="Traffic Filtering" src="https://img.shields.io/badge/traffic--filtering-0277BD?style=flat-square">
</p>

<p align="center">
  <img alt="IoT Security" src="https://img.shields.io/badge/iot--security-5D4037?style=flat-square">
  <img alt="Network Security" src="https://img.shields.io/badge/network--security-283593?style=flat-square">
  <img alt="Edge Security" src="https://img.shields.io/badge/edge--security-AD1457?style=flat-square">
  <img alt="Gateway Security" src="https://img.shields.io/badge/gateway--security-006064?style=flat-square">
  <img alt="TLS SNI Filtering" src="https://img.shields.io/badge/tls--sni--filtering-4E342E?style=flat-square">
</p>

---

## Overview

This project deploys a small-form-factor network security gateway that inspects
forwarded traffic with Suricata and enforces IPS decisions inline. It is designed
for security lab environments where a single board computer sits between a WAN
network and a protected LAN.

The repository includes:

- Ansible playbooks for gateway, Suricata, and rule deployment.
- Foundation shell scripts for step-by-step manual setup.
- A Kali-based IDS/IPS validation harness for attack generation, evidence
  collection, scoring, and reporting.
- Shared inventory and environment configuration for repeatable lab builds.

## Architecture

```text
Internet / WAN
     |
     v
+-----------------------------+
| SBC Gateway                 |
| - LAN/WAN routing           |
| - iptables NFQUEUE          |
| - Suricata IDS/IPS          |
| - Modular rule sets         |
+-----------------------------+
     |
     v
Protected LAN / Victim Hosts
```

Suricata receives forwarded packets through NFQUEUE, evaluates enabled rules,
and can alert or drop traffic depending on the configured rule action and mode.

## Repository Layout

```text
.
├── ansible_deployment/       Gateway, Suricata, and rules playbooks
├── foundation/               Manual setup scripts
├── ids_ips_evaluation/       Kali validation harness and reports
├── images/                   Project icon assets
├── inventory.yaml            Lab inventory and deployment variables
├── main.sh                   Ansible orchestration entry point
├── motd.txt                  Optional login banner content
└── LICENSE
```

## Requirements

Gateway target:

- Debian-based Linux on Raspberry Pi, Orange Pi, or similar SBC.
- Two network interfaces for WAN and LAN forwarding.
- `sudo` privileges.
- Internet access during package and rule installation.

Controller machine:

- Ansible.
- SSH access to the gateway.
- A configured `.env` file containing required local secrets such as
  `trusted_mac`.

Validation machine:

- Kali Linux or a compatible attacker host.
- Python dependencies from `ids_ips_evaluation/requirements.txt`.
- Attack tools such as `nmap`, `hping3`, `hydra`, `swaks`, `tcpdump`, `curl`,
  `dig`, and `netcat`.

## Quick Start

1. Review and edit the lab variables:

```bash
vi inventory.yaml
vi .env
```

2. Run the full gateway deployment:

```bash
chmod +x main.sh
sudo ./main.sh
```

3. Validate the Suricata configuration on the gateway:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl status suricata
```

4. Run the validation harness from Kali:

```bash
cd ids_ips_evaluation
pip install -r requirements.txt
vi config/lab.conf
vi config/targets.conf
sudo ./validation_harness.sh
```

## Deployment Paths

The main orchestration script runs these playbooks in order:

```text
ansible_deployment/gateway_setup_playbook.yaml
ansible_deployment/suricata_setup_playbook.yaml
ansible_deployment/rules_setup_playbook.yaml
```

For manual or educational use, the equivalent shell scripts live in
`foundation/`:

```text
foundation/gateway_setup.sh
foundation/suricata_setup.sh
foundation/rules_setup.sh
```

## Validation Harness

The validation harness in `ids_ips_evaluation/` runs controlled traffic modules
from Kali, collects gateway evidence over SSH/SCP, and produces scoring reports.

See [ids_ips_evaluation/README.md](./ids_ips_evaluation/README.md) for the full
harness workflow, configuration files, attack modules, and scoring model.


## License

This project is licensed under the **BSD 3-Clause License**. See
[LICENSE](./LICENSE) for details.

```text
BSD 3-Clause License

Copyright (c) 2026, Mosudi Isiaka, IoT and Smart Systems, FH Technikum Wien
All rights reserved.
```

---

## Author

**Mosudi Isiaka O.**

- Email: [mosudi.isiaka@gmail.com](mailto:mosudi.isiaka@gmail.com)
- FH Technikum Wien: [io24m006@technikum-wien.at](mailto:io24m006@technikum-wien.at)
- Website: [https://mioemi.com](https://mioemi.com)
- GitHub: [https://github.com/imosudi](https://github.com/imosudi)
