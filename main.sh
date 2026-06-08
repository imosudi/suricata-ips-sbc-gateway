#!/usr/bin/env bash

# =============================================================================
# Suricata IPS SBC Gateway Setup Script
# FH Technikum Wien — IT Security Lab 2026
# This script orchestrates the setup of a Suricata-based Intrusion Prevention System
# on a Single Board Computer (SBC) acting as a network gateway. It performs the following:
#   1. Installs Suricata and dependencies
#   2. Configures network interfaces (LAN/WAN)
#   3. Sets up NFQUEUE for inline packet processing
#   4. Deploys modular rule sets (custom + community)
#   5. Validates configuration and starts Suricata in IPS mode
# Usage:
#   chmod +x main.sh
#   sudo ./main.sh
# ============================================================================= 
set -euo pipefail
IFS=$'\n\t' 

# Load environment variables
if [[ ! -f .env ]]; then
    echo "Error: .env file not found" >&2
    exit 1
fi

set -a
source .env
set +a


# Validate trusted_mac
#[[ -z "${trusted_mac:-}" ]] && err "trusted_mac not set in environment"
#[[ -z "${trusted_mac:-}" ]] && { echo "Error: trusted_mac not set in environment"; exit 1; }

ansible-playbook -K -i inventory.yaml ansible_deployment/gateway_setup_playbook.yaml

ansible-playbook -K -i inventory.yaml ansible_deployment/suricata_setup_playbook.yaml

ansible-playbook -K -i inventory.yaml ansible_deployment/rules_setup_playbook.yaml 

