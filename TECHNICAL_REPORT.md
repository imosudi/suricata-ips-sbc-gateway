<!--p align="center">
  <img src="images/icon.png" alt="Suricata IPS SBC Gateway icon" width="112" height="112">
</p-->

<h1 align="center">Lab Protocol Security Exercise: Suricata IPS SBC Gateway</h1>

<p align="center">
  FH Technikum Wien - IT Security Lab 2026<br>
  Mosudi Isiaka O., io24m006@technikum-wien.at, +4368120662665
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
generates test traffic, collects gateway evidence, and scores IDS/IPS behaviour.

## 1. Project Objectives

The main objectives of the project are:

- Build a low-cost inline IDS/IPS gateway using commodity SBC hardware.
- Configure the SBC as a routed LAN-to-WAN gateway with DHCP, NAT, and packet
  forwarding.
- Integrate Suricata in NFQUEUE inline mode so forwarded packets can be
  inspected before routing decisions complete.
- Provide modular, protocol-specific Suricata rules that can run in alert,
  drop, or bypass modes.
- Add custom rules to detect and block network traffic containing SSL/TLS certificate 
  for domains example.com, example.org, and example.net; string "Big Bang Theory" for 
  both HTTP and Telnet; ICMP Timestamp requests and responses; And more!
- Automate deployment with Ansible while retaining manual shell equivalents for
  learning, auditing, and troubleshooting.
- Validate the deployment with repeatable attack simulations, evidence
  collection, and scoring.

## 2. System Context

The gateway is intended for a lab topology where an SBC is placed between a
WAN-facing network and a protected internal LAN. Client systems behind the
gateway receive addresses from the SBC, route through it, and are monitored by
Suricata as traffic crosses the forwarding path.

<p>
<img src="images/suricata_ips_gateway.png" alt="Suricata IPS SBC Gateway Architecture">
</p>
Figure 1: Suricata IPS SBC Gateway Architecture.


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
suricata-ips-sbc-gateway
├── ansible_deployment
│   ├── gateway_setup_playbook.yaml
│   ├── rules_setup_playbook.yaml
│   └── suricata_setup_playbook.yaml
├── basic_ids_ips_evaluation
│   ├── eval.conf
│   ├── README.md
│   ├── rule-eval
│   │   ├── analysers
│   │   ├── archive
│   │   ├── attacks
│   │   ├── collectors
│   │   ├── config
│   │   ├── logs
│   │   ├── pcaps
│   │   ├── README.md
│   │   ├── reports
│   │   ├── results
│   │   └── run_eval.sh
│   └── run_eval.sh
├── env_sample
├── foundation
│   ├── gateway_setup.sh
│   ├── rules_setup.sh
│   └── suricata_setup.sh
├── generate_pdf.py
├── ids_ips_evaluation
│   ├── analysers
│   │   ├── detection_score.py
│   │   ├── false_positive.py
│   │   ├── grading.py
│   │   ├── ips_score.py
│   │   ├── latency_score.py
│   │   ├── sid_mapper.py
│   │   └── throughput_score.py
│   ├── archive
│   ├── attacks
│   │   ├── benign.sh
│   │   ├── dns.sh
│   │   ├── ftp.sh
│   │   ├── http.sh
│   │   ├── icmp.sh
│   │   ├── policy.sh
│   │   ├── scan.sh
│   │   ├── smtp.sh
│   │   ├── ssh.sh
│   │   └── tls.sh
│   ├── collectors
│   │   ├── environment_collector.sh
│   │   ├── eve_collector.sh
│   │   ├── pcap_collector.sh
│   │   ├── pcap_stop.sh
│   │   ├── performance_collector.sh
│   │   └── stats_collector.sh
│   ├── config
│   │   ├── attack_profiles.yaml
│   │   ├── lab.conf
│   │   ├── rule_mapping.yaml
│   │   ├── scoring.conf
│   │   └── targets.conf
│   ├── logs
│   ├── pcaps
│   ├── README.md
│   ├── reports
│   │   ├── csv_report.py
│   │   ├── html_report.py
│   │   ├── report_generator.py
│   │   └── templates
│   ├── requirements.txt
│   ├── results
│   └── validation_harness.sh
├── ids_ips_evaluation.sh
├── images
│   ├── icon.png
│   ├── icon.svg
│   ├── screenshots
│   │   ├── 00_repository_tree_structure.png
│   │   ├── 01_setup_orchestration.png
│   │   ├── 02_ansible_gateway_deployment_complete.png
│   │   ├── 03_suricata_rules_validation_84_active.png
│   │   ├── 04_ssh_gateway_connection.png
│   │   ├── 05_gateway_system_info_ubuntu_arm64.png
│   │   ├── 06_suricata_journalctl_service_status.png
│   │   └── 07_suricata_installation_success.png
│   ├── suricata_ips_gateway.png
│   └── suricata_ips_gateway.svg
├── inventory.yaml
├── LICENSE
├── main.sh
├── motd.txt
├── README.md
├── secrets.yml
└── TECHNICAL_REPORT.md

```

The `ansible_deployment/` directory is the primary automation path. The
`foundation/` directory mirrors the deployment logic as shell scripts and is
useful when the operator wants direct command-level visibility. The
`basic_ids_ips_evaluation/` directory contains local LAN-side rule validation
for Suricata modules 20, 30, 40, and 50 from a Kali client withing the protected LAN. The
`ids_ips_evaluation/` directory is a separate WAN-side validation harness
intended to run from Kali Linux.

## 4. Deployment Workflow
<p>
<img src="images/screenshots/00_repository_tree_structure.png" alt="Repository tree structure">
</p>
Figure 2: Repository tree structure.

The top-level `main.sh` script orchestrates the Ansible deployment in three
stages:
<p>
<img src="images/screenshots/01_setup_orchestration.png" alt="Ansible gateway deployment complete">
</p>
Figure 3: Ansible gateway deployment complete.


The deployment story begins with the completed gateway provisioning run. The
first screenshot shows the playbook execution finishing successfully, proving
that the SBC gateway was configured and ready for the next stage.

```text
1. ansible_deployment/gateway_setup_playbook.yaml
2. ansible_deployment/suricata_setup_playbook.yaml
3. ansible_deployment/rules_setup_playbook.yaml
```
<p>
<img src="images/screenshots/02_ansible_gateway_deployment_complete.png" alt="Setup orchestration">
</p>
Figure 4: Setup orchestration.


This captures the orchestration sequence. It displays how
`main.sh` invokes the three Ansible playbooks in order, moving from basic
network gateway setup to Suricata installation and rule deployment.
<p>
<img src="images/screenshots/03_suricata_rules_validation_84_active.png" alt="Suricata rules validation">
</p>
Figure 5: Suricata rules validation.


The Suricata rule validation. It shows 84 active
rules loaded successfully, confirming that the modular rule set was enabled and
validated before the gateway entered production.
<p>
<img src="images/screenshots/04_ssh_gateway_connection.png" alt="SSH gateway connection">
</p>
Figure 6: SSH gateway connection.


After deployment, remote access is verified. The SSH connection 
proves the gateway host is reachable and manageable over the network.
<p>
<img src="images/screenshots/05_gateway_system_info_ubuntu_arm64.png" alt="Gateway system info">
</p>
Figure 7: IPS Gateway system info.

The gateway system information clearly indicating Ubuntu ARM64 platform,
providing hardware and OS details for the SBC platform used in the lab.
<p>
<img src="images/screenshots/06_suricata_journalctl_service_status.png" alt="Suricata journalctl service status">
</p>
Figure 8: Suricata journalctl service status.


The service status proves Suricata is running under systemd. It
shows `journalctl` output for the Suricata service and confirms the daemon is
active after the deployment.

<p>
<img src="images/screenshots/07_suricata_installation_success.png" alt="Suricata installation success">
</p>
Figure 9: Suricata installation details




The inventory is parameterised through `inventory.yaml` and environment values
such as `TARGET_IP`, `ANSIBLE_USER`, `ANSIBLE_SSH_KEY`, `WIFI_SSID`, and
`WIFI_PASSWORD`. A local `.env` file is used for these sensitive information as environmental 
variables.

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
/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml \
     --pidfile /run/suricata.pid
```
<div style="page-break-after: always;"></div>

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

## 7. Importance for IoT Deployments

IoT deployments often contain devices with limited CPU capacity, memory,
storage, battery budget, and operating system flexibility. These constraints
create a form of resource poverty: even when strong security mechanisms are
well understood, many IoT devices cannot easily support them without affecting
their main function, increasing cost, or exceeding their hardware limits.

Typical challenges include:

- Limited processing power for encryption, deep logging, endpoint protection,
  or complex authentication workflows.
- Minimal storage for certificates, logs, package updates, and security agents.
- Vendor firmware that cannot be modified or audited easily.
- Long device lifetimes with short vendor support windows.
- Weak default credentials or inconsistent credential rotation support.
- Missing support for modern TLS versions, certificate validation, or mutual
  authentication.
- Difficulty deploying and renewing SSL/TLS certificates on each device,
  including self-generated certificates.
- Inconsistent update mechanisms across different vendors and device classes.

Because of these limitations, defending every IoT device individually is often
unrealistic. A device-by-device strategy requires each endpoint to implement
secure configuration, certificate lifecycle management, logging, patching,
firewalling, and intrusion detection. In a mixed IoT network, this becomes
operationally expensive and technically uneven.

The Suricata IPS SBC Gateway supports a perimeter defense strategy for such
environments. Instead of relying only on each IoT device to protect itself, the
gateway becomes a shared enforcement and observation point for the network
segment. All devices behind the gateway benefit from common controls:

- Centralised traffic inspection before packets leave or enter the protected
  LAN.
- Protocol and policy enforcement for devices that cannot run local security
  agents.
- Detection of scanning, brute-force attempts, suspicious DNS behaviour, unsafe
  plaintext protocols, and unwanted outbound services.
- A single place to collect alerts, packet captures, counters, and performance
  evidence.
- Controlled access paths into the IoT segment instead of exposing each device
  directly to upstream networks.
- Easier experimentation with IDS and IPS policies before applying them to
  production-like device groups.

This model does not remove the need for secure device configuration, but it
reduces dependence on perfect endpoint security. Even devices with weak or
limited built-in controls can be placed behind a stronger network boundary.

### 7.1 Certificate and Access Challenges

SSL/TLS certificate management is a common pain point in IoT systems. Some
devices do not support modern certificate chains, some only support self-signed
certificates, and others expose web interfaces that are difficult to automate.
Even when self-generated certificates are possible, operators still need to
handle certificate generation, distribution, trust, renewal, and revocation for
each device.

A gateway-based design can reduce this burden by limiting which systems can
reach device management interfaces. For example, the gateway can enforce policy
so that administrative access is allowed only from trusted IP addresses, VPN
subnets, jump hosts, or management workstations. Suricata rules and firewall
rules can then monitor and restrict traffic to sensitive IoT services such as
HTTP, HTTPS, SSH, Telnet, FTP, MQTT, CoAP, or vendor-specific ports.

This is especially useful for devices that only support self-signed
certificates. The gateway cannot magically make an insecure device interface
secure, but it can reduce exposure by ensuring that only authorised management
paths can reach that interface. It can also alert on suspicious access attempts,
unexpected protocols, brute-force behaviour, or data exfiltration patterns.

### 7.2 Secure Connectivity for Devices Behind the Gateway

Devices behind the same IDS/IPS gateway gain the opportunity to communicate
through a controlled trust boundary. The gateway can separate normal device
traffic from administrative traffic, enforce outbound policy, and detect
unexpected lateral or internet-bound behaviour.

Examples include:

- Allowing IoT devices to reach only required cloud endpoints or update servers.
- Blocking or alerting on direct access to risky services such as Telnet or FTP.
- Monitoring DNS queries for suspicious domains or dynamic DNS abuse.
- Restricting management access to selected administrators.
- Detecting scans between devices on the protected side of the network.
- Creating a shared logging point for devices that cannot produce useful local
  security logs.

This perimeter approach is valuable in smart homes, teaching labs, industrial
prototypes, environmental monitoring systems, and small research deployments.
It offers a practical middle ground: individual devices should still be
configured as securely as possible, but the network gateway provides an
additional defensive layer that is easier to manage, observe, and update.

## 8. Validation Harness

The project provides two complementary validation harnesses:

- `basic_ids_ips_evaluation/` is designed for LAN-side rule validation of
  Suricata modules 20, 30, 40, and 50 from a Kali client inside the protected
  LAN.
- `ids_ips_evaluation/` is designed for WAN-side validation, evidence
  collection, and scoring from a Kali attacker outside the protected network.

The WAN-side harness in `ids_ips_evaluation/` is designed to run from Kali
Linux as an attacker and evidence collection host.

Its main functions are:

- Generate traffic with attack modules.
- Pull logs and runtime evidence from the Suricata gateway over SSH/SCP.
- Capture local and gateway-side PCAP evidence.
- Score detection, blocking, latency, throughput, and false positives.
- Generate JSON, CSV, and HTML reports.

### 8.1 Attack Modules

| Module | Tools | Coverage |
|--------|-------|----------|
| `icmp` | `hping3`, `ping` | Floods, oversised packets, timestamp traffic. |
| `scan` | `nmap` | SYN, NULL, XMAS, version, and OS scans. |
| `dns` | `dig` | NXDOMAIN, ANY, and tunnel-like queries. |
| `ssh` | `ssh`, `hydra` | Brute force, banner grab, credential testing. |
| `http` | `curl`, `nikto` | SQL injection, XSS, traversal, scanner user agents. |
| `tls` | `openssl` | Weak ciphers, legacy protocols, certificate checks. |
| `ftp` | `ftp`, `hydra` | Anonymous login and credential testing. |
| `smtp` | `nc`, `swaks` | Open relay and VRFY/EXPN enumeration. |
| `policy` | `nc`, `curl` | Tor ports, BitTorrent DHT, IRC, HTTP CONNECT. |
| `benign` | `curl`, `ping`, `dig` | False-positive baseline traffic. |

### 8.2 Evidence Collection

| Collector | Evidence |
|-----------|----------|
| `eve_collector.sh` | Suricata `eve.json` alerts and events. |
| `stats_collector.sh` | Suricata counters or `stats.log`. |
| `pcap_collector.sh` | Local tcpdump PCAPs and gateway pcap-log data. |
| `performance_collector.sh` | CPU and memory samples from Kali and gateway. |
| `environment_collector.sh` | Tool versions, Suricata version, and rule state. |

### 8.3 Scoring Model

The harness computes:

| Dimension | Weight | Source |
|-----------|--------|--------|
| Detection rate | 35% | Alert coverage per attack module in EVE JSON. |
| IPS block rate | 25% | `blocked` action events in IPS mode. |
| Latency impact | 20% | Gateway load during attack versus baseline. |
| False positives | 20% | Alerts generated during benign traffic. |


<div style="page-break-after: always;"></div>


Grades are assigned as:

| Grade | Score |
|-------|-------|
| A | 90 or higher |
| B | 80 to 89 |
| C | 70 to 79 |
| D | 60 to 69 |
| F | Below 60 |

## 9. Migration from `ids_ips_evaluation.sh` to `ids_ips_evaluation/`

The project originally included `ids_ips_evaluation.sh` as a single-file Kali
evaluation client. That script was valuable as a first working prototype
because it placed the complete test flow in one readable shell program:

- Prompt for the target host, network interface, web URL, gateway IP, and SSH
  user.
- Check and install required tools such as `nmap`, `hping3`, `hydra`,
  `sqlmap`, `tcpdump`, `tcpreplay`, `iperf3`, `jq`, and `ssh`.
- Start a local packet capture.
- Run reconnaissance, flood, malformed packet, brute-force, SQL injection,
  throughput, and replay tests.
- Retrieve Suricata alerts and drop events from the gateway through SSH.
- Produce a timestamped local report directory with logs, PCAP data, alert
  summaries, throughput output, and a final text report.

This monolithic approach was useful during early development because it reduced
the number of moving parts. The full evaluation concept could be tested quickly
from one entry point, and every command was visible in sequence. However, as the
evaluation scope grew, the single-script model became harder to maintain.
Traffic generation, evidence collection, scoring, configuration, and reporting
all lived in the same file, which made targeted changes riskier and made it
harder to reuse individual parts of the workflow.

The newer `ids_ips_evaluation/` directory keeps the same core idea but turns it
into a modular validation harness:

```text
ids_ips_evaluation/
├── validation_harness.sh   Main orchestrator
├── config/                 Lab, target, scoring, profile, and SID mapping data
├── attacks/                One attack module per protocol or behaviour
├── collectors/             Evidence collection from Kali and gateway
├── analysers/              Python scoring and attribution logic
├── reports/                HTML, CSV, and aggregate report generation
├── logs/                   Collected EVE JSON and session logs
├── pcaps/                  Local and gateway packet captures
├── results/                Scoring output and final reports
└── archive/                Compressed historical sessions
```

The migration improves the project in several ways:

| Area | Original `ids_ips_evaluation.sh` | Modular `ids_ips_evaluation/` |
|------|----------------------------------|-------------------------------|
| Configuration | Interactive prompts and inline variables. | Reusable files such as `config/lab.conf`, `config/targets.conf`, and `config/scoring.conf`. |
| Attacks | Fixed command sequence in one script. | Separate protocol modules under `attacks/`. |
| Collection | Inline SSH, jq, tcpdump, and report extraction. | Dedicated collectors for EVE, stats, PCAP, performance, and environment data. |
| Analysis | Basic alert summaries and throughput extraction. | Python analysers for detection, IPS blocking, latency, throughput, false positives, grading, and SID mapping. |
| Reporting | Plain text final report. | JSON results plus CSV and HTML report generation. |
| Maintainability | Any change risks affecting the entire workflow. | Modules can be tested and adjusted independently. |
| Extensibility | Adding a test expands the already-large shell file. | New attacks, collectors, or analysers can be added as new files. |

The migration should be understood as an architectural refactor rather than a
complete replacement of the original idea. The original script defines the
prototype workflow and remains useful as a compact reference for the evaluation
sequence. The directory-based harness formalises that workflow into smaller
components with clearer responsibilities.

The recommended long-term role of `ids_ips_evaluation.sh` is one of the
following:

- Keep it as a legacy prototype and document that new work should target
  `ids_ips_evaluation/`.
- Convert it into a thin compatibility wrapper that calls
  `ids_ips_evaluation/validation_harness.sh`.
- Remove it after all functionality has been mapped into the modular harness
  and users have migrated to the new interface.

For this project, the modular harness is the preferred path because it better
supports repeatable testing, scoring, reporting, and future expansion.

<div style="page-break-after: always;"></div>


## 10. Operational Procedures

### 10.1 Deploy the Gateway

```bash
git clone https://github.com/imosudi/suricata-ips-sbc-gateway.git
cd suricata-ips-sbc-gateway
vi inventory.yaml
vi .env # or mv .env.sample .env; vi .env
chmod +x main.sh
sudo ./main.sh
```

### 10.2 Validate Suricata on the Gateway

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl status suricata
sudo iptables -L FORWARD -n -v --line-numbers
sudo tail -f /var/log/suricata/fast.log
```

### 10.3 Run the Validation Harness

```bash
cd ids_ips_evaluation
pip install -r requirements.txt
vi config/lab.conf
vi config/targets.conf
sudo ./validation_harness.sh
```

### 10.4 Reload Rules

After editing rules on the gateway:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo kill -USR2 $(cat /run/suricata.pid)
```

If the reload does not behave as expected, restart the service:

```bash
sudo systemctl restart suricata
```

## 11. Assumptions and Constraints

The current implementation assumes:

- The SBC is a Debian-based Orange Pi, Raspberry Pi, or comparable single board
  computer with systemd, Netplan, iptables, and `netfilter-persistent`
  available.
- The SBC has an Ethernet NIC named `eth0`, used as the protected LAN
  interface.
- The SBC has a WLAN interface named `wlan0`, used as the upstream WAN
  interface.
- The WAN interface can obtain an upstream address through DHCP and remains
  reachable for SSH during provisioning.
- The LAN interface is dedicated to the protected lab network and is configured
  as `10.10.10.1/24` by default.
- The LAN is IPv4-based and uses the default `10.10.10.0/24` subnet unless
  changed in `inventory.yaml`.
- LAN clients obtain DHCP leases from the SBC in the default
  `10.10.10.100` - `10.10.10.200` range.
- No other DHCP server is active on the protected LAN segment.
- The control node has SSH and sudo access to the gateway.
- The Ansible controller has a local `.env` file with `TARGET_IP`,
  `ANSIBLE_USER`, `ANSIBLE_SSH_KEY`, `WIFI_SSID`, `WIFI_PASSWORD`, and trusted
  host values used by the inventory and playbooks.
- The deployment can temporarily modify network configuration, iptables rules,
  DHCP service settings, Suricata configuration, and the login MOTD on the SBC.
- The validation harness can SSH/SCP into the gateway to collect evidence.
- Suricata is inserted inline through NFQUEUE queue `0`.
- HTTPS payload inspection is not performed; TLS rules rely on metadata such as
  SNI or certificate subjects.

Important constraints:

- NFQUEUE introduces userspace packet inspection overhead.
- Performance depends heavily on SBC CPU, memory, storage, and network
  interface quality.
- Wi-Fi WAN throughput and stability may limit end-to-end gateway performance.
- Some Suricata keywords behave differently depending on capture mode. For
  example, Ethernet MAC matching is better handled in iptables when operating
  through NFQUEUE.
- Encrypted application payloads are not visible without TLS interception.

## 12. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Misconfigured interface names | Gateway loses routing or provisioning fails. | Validate `lan_iface` and `wan_iface` before deployment. |
| Invalid Suricata rules | Suricata fails to start or reload. | Run `suricata -T` before applying changes. |
| NFQUEUE service failure | Traffic may be interrupted or bypassed depending on rules. | Define explicit fail-open/fail-closed policy and monitor service health. |
| Excessive rule load on SBC | Packet loss, latency, or dropped throughput. | Keep rules scoped, test performance, and disable unnecessary modules. |
| Secrets in local files | Credential exposure. | Keep `.env` and private keys out of version control. |
| False positives | Legitimate traffic may be blocked in IPS mode. | Run modules in IDS mode first, analyze benign baseline, then promote to IPS. |

## 13. Evaluation Criteria

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
- The final harness report shows detection and blocking behaviour consistent with
  the configured rule modes.

## 14. Future Work

Recommended improvements include:

- Add CI checks for shell syntax, Ansible linting, and Markdown links.
- Convert `ids_ips_evaluation.sh` into a compatibility wrapper or formally
  retire it after migration is complete (On going).
- Add example IoT segmentation profiles for device groups such as cameras,
  sensors, smart plugs, and management workstations.
- Add optional VPN or jump-host guidance for secure remote administration of
  devices behind the IDS/IPS gateway.
- Add an explicit rollback playbook for network and Suricata configuration.
- Separate secrets handling from `.env` copying by using Ansible Vault or a
  dedicated secret store.
- Add IPv6 forwarding and Suricata coverage where required.
- Add performance benchmarks for different SBC models and rule profiles.
- Add dashboards for EVE JSON, counters, and long-running gateway health.
- Add automated rule promotion workflow from IDS to IPS after validation.
- Add explicit fail-open/fail-closed documentation for NFQUEUE failure modes.

## 15. Conclusion

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
- [Intrusion Detection System (IDS) Vs Intrusion Prevention System (IPS)](https://www.checkpoint.com/cyber-hub/network-security/what-is-an-intrusion-detection-system-ids/ids-vs-ips/)
- [Suricata](https://suricata.io/)
- [Network Address Translation](https://www.vmware.com/topics/network-address-translation)
- [Ansible](https://www.ansible.com/)
- [Ansible Collaborative](https://www.redhat.com/en/ansible-collaborative)
- [Ansible community documentation](https://docs.ansible.com/)
- [Netplan](https://netplan.io/)
- [Netfilter](https://www.netfilter.org/)
- [Single-board computer (SBC)](https://en.wikipedia.org/wiki/Single-board_computer)
- [Ornage Pi](https://www.orangepi.org/)
- [Raspberry Pi](http://www.raspberrypi.org/)
- [Orange Pi 3](http://www.orangepi.org/html/hardWare/computerAndMicrocontrollers/details/Orange-Pi-3.html)
- [Debian](https://www.debian.org/)
- [Ubuntu](https://ubuntu.com/)
- [Kali Linux](https://kali.org/)

## Appendix

###
Curl hanging TLS blocked example.com/net/org


<p>
<img src="images/screenshots/08_curl_hanging_tls_blocked_example_com_net_org.png" alt="curl hanging TLS blocked example.com/net/org">
</p>
Figure 10: Curl hanging TLS blocked example.com/net/org

###
<p>
<img src="images/screenshots/09_curl_mioemi_com_allowed_passes_through.png" alt="curl mioemi.com allowed passes through">
</p>
Figure 11: Curl mioemi.com allowed passes through

###
<p>
<img src="images/screenshots/10_suricata_drop_confirmed_example_com_net_org_fast_log.png" alt="Suricata drop confirmed example.com/net/org fast log">
</p>
Figure 12: Suricata drop confirmed example.com/net/org fast log

<div style="page-break-after: always;"></div>

###
To generate PDF version from the Markdown file:
```bash
cd suricata-ips-sbc-gateway  
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python generate_pdf.py
```

