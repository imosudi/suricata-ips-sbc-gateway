<p align="center">
  <img src="images/icon.png" alt="Suricata IPS SBC Gateway icon" width="112" height="112">
</p>

<h1 align="center">Technical Report: Suricata IPS SBC Gateway</h1>

<p align="center">
  FH Technikum Wien - IT Security Lab 2026<br>
  Mosudi Isiaka O.
</p>

---

## Abstract

This project implements an inline Intrusion Detection and Prevention System
(IDS/IPS) gateway on a Debian-based single board computer (SBC), such as a
Raspberry Pi or Orange Pi. The gateway forwards traffic between a protected LAN
and an upstream WAN interface while directing forwarded packets through
Suricata using Linux NFQUEUE. The result is a compact security appliance that
can route, inspect, alert on, and optionally drop traffic based on modular
Suricata rule sets.

The repository provides two complementary deployment paths: Ansible playbooks
for repeatable automated provisioning and shell scripts for manual,
step-by-step setup. It also includes a Kali-based validation harness that
generates test traffic, collects gateway evidence, and scores IDS/IPS behavior.

## 1. Project Objectives

The main objectives of the project are:

- Build a low-cost inline IDS/IPS gateway using commodity SBC hardware.
- Configure the SBC as a routed LAN-to-WAN gateway with DHCP, NAT, and packet
  forwarding.
- Integrate Suricata in NFQUEUE inline mode so forwarded packets can be
  inspected before routing decisions complete.
- Provide modular, protocol-specific Suricata rules that can run in alert,
  drop, or bypass modes.
- Automate deployment with Ansible while retaining manual shell equivalents for
  learning, auditing, and troubleshooting.
- Validate the deployment with repeatable attack simulations, evidence
  collection, and scoring.

## 2. System Context

The gateway is intended for a lab topology where an SBC is placed between a
WAN-facing network and a protected internal LAN. Client systems behind the
gateway receive addresses from the SBC, route through it, and are monitored by
Suricata as traffic crosses the forwarding path.

```text
Internet / WAN
     |
     v
+------------------------------------------------+
| SBC Gateway                                    |
|                                                |
|  wlan0 / WAN: DHCP upstream                    |
|  eth0  / LAN: 10.10.10.1/24                   |
|                                                |
|  - Netplan networking                          |
|  - ISC DHCP server                             |
|  - IPv4 forwarding                             |
|  - iptables NAT and FORWARD control            |
|  - NFQUEUE handoff to Suricata                 |
|  - Modular Suricata rules                      |
+------------------------------------------------+
     |
     v
Protected LAN clients: 10.10.10.100 - 10.10.10.200
```

The default inventory uses:

| Setting | Default |
|---------|---------|
| LAN interface | `eth0` |
| WAN interface | `wlan0` |
| Gateway LAN IP | `10.10.10.1/24` |
| LAN subnet | `10.10.10.0/24` |
| DHCP range | `10.10.10.100` - `10.10.10.200` |
| DNS servers | `9.9.9.9`, `1.1.1.1` |
| NFQUEUE number | `0` |
| Suricata config | `/etc/suricata/suricata.yaml` |
| Suricata rules | `/etc/suricata/rules` |
| Suricata logs | `/var/log/suricata` |

## 3. Repository Structure

```text
.
├── ansible_deployment/
│   ├── gateway_setup_playbook.yaml
│   ├── suricata_setup_playbook.yaml
│   └── rules_setup_playbook.yaml
├── foundation/
│   ├── gateway_setup.sh
│   ├── suricata_setup.sh
│   └── rules_setup.sh
├── ids_ips_evaluation/
│   ├── attacks/
│   ├── collectors/
│   ├── analyzers/
│   ├── reports/
│   ├── config/
│   └── validation_harness.sh
├── images/
│   ├── icon.png
│   └── icon.svg
├── inventory.yaml
├── main.sh
├── README.md
└── LICENSE
```

The `ansible_deployment/` directory is the primary automation path. The
`foundation/` directory mirrors the deployment logic as shell scripts and is
useful when the operator wants direct command-level visibility. The
`ids_ips_evaluation/` directory is a separate test harness intended to run from
Kali Linux.

## 4. Deployment Workflow

The top-level `main.sh` script orchestrates the Ansible deployment in three
stages:

```text
1. ansible_deployment/gateway_setup_playbook.yaml
2. ansible_deployment/suricata_setup_playbook.yaml
3. ansible_deployment/rules_setup_playbook.yaml
```

The inventory is parameterized through `inventory.yaml` and environment values
such as `TARGET_IP`, `ANSIBLE_USER`, `ANSIBLE_SSH_KEY`, `WIFI_SSID`, and
`WIFI_PASSWORD`. A local `.env` file is used for sensitive or environment-
specific configuration.

### 4.1 Gateway Provisioning

`gateway_setup_playbook.yaml` prepares the SBC as a network gateway. Its major
tasks are:

- Verify privilege level and confirm the LAN interface exists.
- Copy and parse `.env` values for Wi-Fi configuration.
- Bootstrap DNS resolution.
- Update the system and install core networking packages.
- Configure Netplan with a static LAN address and DHCP WAN address.
- Enable persistent IPv4 forwarding with sysctl.
- Configure iptables NAT and FORWARD rules.
- Persist firewall rules with `netfilter-persistent`.
- Configure and start ISC DHCP server for protected LAN clients.

This stage establishes basic routing before Suricata is inserted into the
forwarding path.

### 4.2 Suricata IPS Provisioning

`suricata_setup_playbook.yaml` installs and configures Suricata in NFQUEUE mode.
Its major tasks are:

- Verify that IP forwarding is already enabled.
- Install Suricata and required dependencies.
- Create Suricata log and rule directories.
- Back up `/etc/suricata/suricata.yaml`.
- Set `HOME_NET` to the configured LAN subnet.
- Insert a clean `nfq` configuration block.
- Remove or disable conflicting AF_PACKET-oriented configuration.
- Ensure `local.rules` is included in the Suricata rule files.
- Validate the Suricata configuration with `suricata -T`.
- Configure iptables to send forwarded packets to NFQUEUE.
- Create a systemd override so Suricata starts with `-q 0`.
- Enable, restart, and verify the Suricata service.

The systemd override runs Suricata with a command equivalent to:

```bash
/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
```

### 4.3 Modular Rule Deployment

`rules_setup_playbook.yaml` creates a modular rule engine under
`/etc/suricata/rules/available` and `/etc/suricata/rules/enabled`. Rule modules
are controlled by the `suricata_rule_modules` map in `inventory.yaml`, where
each module can be enabled and assigned a mode.

The supported rule modes are:

| Mode | Suricata action | Purpose |
|------|-----------------|---------|
| `ids` | `alert` | Detect and log traffic without blocking it. |
| `ips` | `drop` | Detect and block matching traffic inline. |
| `bypass` | `pass` | Allow trusted traffic to pass. |

The generated rule modules include:

| Rule file | Coverage |
|-----------|----------|
| `10_trusted.rules` | Trusted admin IP bypass logic. |
| `20_icmp.rules` | ICMP timestamp and flood detection. |
| `30_http.rules` | HTTP content, SQL injection, traversal, and scanner detection. |
| `40_tls.rules` | TLS SNI and certificate subject detection. |
| `50_telnet.rules` | Telnet cleartext content and policy detection. |
| `60_scan.rules` | Port scan detection. |
| `70_dns.rules` | DNS anomaly and dynamic DNS detection. |
| `80_ssh.rules` | SSH detection and brute-force-oriented policy. |
| `90_ftp.rules` | FTP detection. |
| `100_smtp.rules` | SMTP detection. |
| `110_policy.rules` | Policy enforcement for unwanted applications and ports. |
| `120_local.rules` | Local test and extension rules. |

The lab-specific rules include plaintext HTTP and Telnet detection for the
string `Big Bang Theory`, as well as TLS SNI and certificate checks for
`example.com`, `example.org`, and `example.net`.

## 5. Packet Processing Design

The packet path is:

```text
LAN client
  -> eth0
  -> Linux FORWARD chain
  -> NFQUEUE queue 0
  -> Suricata inspection
  -> verdict: accept/drop
  -> NAT via wlan0
  -> WAN
```

NFQUEUE is used because it lets a userspace inspection engine make packet
verdicts for forwarded traffic. In IDS mode, rules generally alert and allow
traffic to continue. In IPS mode, rules with `drop` actions instruct Suricata to
return a blocking verdict for matching packets.

The gateway keeps an `ESTABLISHED,RELATED` forwarding rule near the top of the
FORWARD chain for return traffic. New or relevant forwarded flows are passed
through NFQUEUE for inspection.

## 6. Security Controls

The deployment applies several controls:

- Default FORWARD handling is restricted and explicitly managed.
- LAN clients are NATed outbound through the WAN interface.
- Suricata inspects transit traffic inline.
- Trusted administration can be handled through bypass rules and inventory
  variables.
- Protocol-specific rules separate detection concerns by service area.
- Suricata configuration is validated before the service is started.
- iptables rules and system configuration are persisted across reboots.

The design is most appropriate for lab and small network environments. For
production networks, additional controls would be required, including robust
secrets management, hardening, backup policy, monitoring, and fail-open/fail-
closed decisions.

## 7. Validation Harness

The validation harness in `ids_ips_evaluation/` is designed to run from Kali
Linux as an attacker and evidence collection host.

Its main functions are:

- Generate traffic with attack modules.
- Pull logs and runtime evidence from the Suricata gateway over SSH/SCP.
- Capture local and gateway-side PCAP evidence.
- Score detection, blocking, latency, throughput, and false positives.
- Generate JSON, CSV, and HTML reports.

### 7.1 Attack Modules

| Module | Tools | Coverage |
|--------|-------|----------|
| `icmp` | `hping3`, `ping` | Floods, oversized packets, timestamp traffic. |
| `scan` | `nmap` | SYN, NULL, XMAS, version, and OS scans. |
| `dns` | `dig` | NXDOMAIN, ANY, and tunnel-like queries. |
| `ssh` | `ssh`, `hydra` | Brute force, banner grab, credential testing. |
| `http` | `curl`, `nikto` | SQL injection, XSS, traversal, scanner user agents. |
| `tls` | `openssl` | Weak ciphers, legacy protocols, certificate checks. |
| `ftp` | `ftp`, `hydra` | Anonymous login and credential testing. |
| `smtp` | `nc`, `swaks` | Open relay and VRFY/EXPN enumeration. |
| `policy` | `nc`, `curl` | Tor ports, BitTorrent DHT, IRC, HTTP CONNECT. |
| `benign` | `curl`, `ping`, `dig` | False-positive baseline traffic. |

### 7.2 Evidence Collection

| Collector | Evidence |
|-----------|----------|
| `eve_collector.sh` | Suricata `eve.json` alerts and events. |
| `stats_collector.sh` | Suricata counters or `stats.log`. |
| `pcap_collector.sh` | Local tcpdump PCAPs and gateway pcap-log data. |
| `performance_collector.sh` | CPU and memory samples from Kali and gateway. |
| `environment_collector.sh` | Tool versions, Suricata version, and rule state. |

### 7.3 Scoring Model

The harness computes:

| Dimension | Weight | Source |
|-----------|--------|--------|
| Detection rate | 35% | Alert coverage per attack module in EVE JSON. |
| IPS block rate | 25% | `blocked` action events in IPS mode. |
| Latency impact | 20% | Gateway load during attack versus baseline. |
| False positives | 20% | Alerts generated during benign traffic. |

Grades are assigned as:

| Grade | Score |
|-------|-------|
| A | 90 or higher |
| B | 80 to 89 |
| C | 70 to 79 |
| D | 60 to 69 |
| F | Below 60 |

## 8. Operational Procedures

### 8.1 Deploy the Gateway

```bash
vi inventory.yaml
vi .env
chmod +x main.sh
sudo ./main.sh
```

### 8.2 Validate Suricata on the Gateway

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl status suricata
sudo iptables -L FORWARD -n -v --line-numbers
sudo tail -f /var/log/suricata/fast.log
```

### 8.3 Run the Validation Harness

```bash
cd ids_ips_evaluation
pip install -r requirements.txt
vi config/lab.conf
vi config/targets.conf
sudo ./validation_harness.sh
```

### 8.4 Reload Rules

After editing rules on the gateway:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo kill -USR2 $(cat /run/suricata.pid)
```

If the reload does not behave as expected, restart the service:

```bash
sudo systemctl restart suricata
```

## 9. Assumptions and Constraints

The current implementation assumes:

- The SBC has one LAN interface and one WAN interface.
- The WAN interface can obtain an upstream address through DHCP.
- The LAN is IPv4-based and uses the default `10.10.10.0/24` subnet unless
  changed in `inventory.yaml`.
- The operator has SSH and sudo access to the gateway.
- The validation harness can SSH/SCP into the gateway to collect evidence.
- HTTPS payload inspection is not performed; TLS rules rely on metadata such as
  SNI or certificate subjects.

Important constraints:

- NFQUEUE introduces userspace packet inspection overhead.
- Performance depends heavily on SBC CPU, memory, storage, and network
  interface quality.
- Some Suricata keywords behave differently depending on capture mode. For
  example, Ethernet MAC matching is better handled in iptables when operating
  through NFQUEUE.
- Encrypted application payloads are not visible without TLS interception.

## 10. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Misconfigured interface names | Gateway loses routing or provisioning fails. | Validate `lan_iface` and `wan_iface` before deployment. |
| Invalid Suricata rules | Suricata fails to start or reload. | Run `suricata -T` before applying changes. |
| NFQUEUE service failure | Traffic may be interrupted or bypassed depending on rules. | Define explicit fail-open/fail-closed policy and monitor service health. |
| Excessive rule load on SBC | Packet loss, latency, or dropped throughput. | Keep rules scoped, test performance, and disable unnecessary modules. |
| Secrets in local files | Credential exposure. | Keep `.env` and private keys out of version control. |
| False positives | Legitimate traffic may be blocked in IPS mode. | Run modules in IDS mode first, analyze benign baseline, then promote to IPS. |

## 11. Evaluation Criteria

A successful deployment should satisfy the following:

- LAN clients receive DHCP leases from the gateway.
- LAN clients can reach the WAN through NAT.
- IP forwarding remains enabled after reboot.
- iptables FORWARD traffic reaches NFQUEUE.
- Suricata runs with the expected queue number.
- Suricata logs alerts to `/var/log/suricata`.
- Enabled IDS rules generate alerts during matching tests.
- Enabled IPS rules drop matching traffic.
- The validation harness can collect EVE, stats, PCAP, and performance evidence.
- The final harness report shows detection and blocking behavior consistent with
  the configured rule modes.

## 12. Future Work

Recommended improvements include:

- Add CI checks for shell syntax, Ansible linting, and Markdown links.
- Add an explicit rollback playbook for network and Suricata configuration.
- Separate secrets handling from `.env` copying by using Ansible Vault or a
  dedicated secret store.
- Add IPv6 forwarding and Suricata coverage where required.
- Add performance benchmarks for different SBC models and rule profiles.
- Add dashboards for EVE JSON, counters, and long-running gateway health.
- Add automated rule promotion workflow from IDS to IPS after validation.
- Add explicit fail-open/fail-closed documentation for NFQUEUE failure modes.

## 13. Conclusion

The Suricata IPS SBC Gateway project demonstrates how a low-cost Debian-based
single board computer can be converted into an inline security gateway. By
combining Linux routing, NAT, DHCP, iptables NFQUEUE, Suricata, modular rule
deployment, and a Kali validation harness, the project provides both a working
security appliance and a repeatable learning environment for IDS/IPS design.

The implementation is intentionally transparent: Ansible provides repeatable
automation, shell scripts preserve command-level clarity, and the validation
harness gives measurable feedback about detection, prevention, and operational
impact.

## References

- [README.md](./README.md)
- [ids_ips_evaluation/README.md](./ids_ips_evaluation/README.md)
- [inventory.yaml](./inventory.yaml)
- [ansible_deployment/gateway_setup_playbook.yaml](./ansible_deployment/gateway_setup_playbook.yaml)
- [ansible_deployment/suricata_setup_playbook.yaml](./ansible_deployment/suricata_setup_playbook.yaml)
- [ansible_deployment/rules_setup_playbook.yaml](./ansible_deployment/rules_setup_playbook.yaml)
