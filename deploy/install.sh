#!/usr/bin/env bash
# ==============================================================================
# AegisFlow - Automated Production Server Installation Script
# Supports: Ubuntu 22.04/24.04 LTS, Debian 12, Rocky Linux 9, RHEL 9
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   AegisFlow Production Server Installer                              ${NC}"
echo -e "${BLUE}   Carrier-Grade Flow Telemetry & Observability Engine                 ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root or with sudo.${NC}"
    exit 1
fi

INSTALL_DIR="/opt/aegisflow"
SERVICE_USER="aegisflow"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${GREEN}[*] Step 1: Installing system packages...${NC}"
if command -v apt-get &> /dev/null; then
    apt-get update -y
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        build-essential \
        libsnmp-dev \
        git \
        curl \
        ufw
elif command -v dnf &> /dev/null; then
    dnf install -y epel-release || true
    dnf install -y \
        python3 \
        python3-pip \
        gcc \
        gcc-c++ \
        net-snmp-devel \
        git \
        curl \
        firewalld
fi

echo -e "${GREEN}[*] Step 2: Creating service user & directories...${NC}"
if ! id -u "${SERVICE_USER}" &>/dev/null; then
    useradd -r -s /bin/false -d "${INSTALL_DIR}" "${SERVICE_USER}"
    echo -e "${GREEN}[+] Created service user: ${SERVICE_USER}${NC}"
fi

mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/data"
mkdir -p "${INSTALL_DIR}/config"
mkdir -p "${INSTALL_DIR}/reports/spool"

echo -e "${GREEN}[*] Step 3: Copying repository files to ${INSTALL_DIR}...${NC}"
cp -ru "${REPO_ROOT}"/* "${INSTALL_DIR}/" || cp -r "${REPO_ROOT}"/* "${INSTALL_DIR}/"

echo -e "${GREEN}[*] Step 4: Creating Python virtual environment...${NC}"
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

echo -e "${GREEN}[*] Step 5: Applying high-throughput Linux UDP kernel tuning...${NC}"
if [ -f "${INSTALL_DIR}/deploy/sysctl-tuning.conf" ]; then
    cp "${INSTALL_DIR}/deploy/sysctl-tuning.conf" /etc/sysctl.d/99-aegisflow.conf
    sysctl -p /etc/sysctl.d/99-aegisflow.conf || true
fi

echo -e "${GREEN}[*] Step 6: Setting file permissions...${NC}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chmod -R 750 "${INSTALL_DIR}"
chmod -R 770 "${INSTALL_DIR}/data"
chmod -R 770 "${INSTALL_DIR}/reports/spool"

echo -e "${GREEN}[*] Step 7: Configuring firewall ports...${NC}"
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    echo -e "${YELLOW}[*] Opening UFW ports: 8080/tcp, 2055/udp, 2056/udp, 4739/udp, 6343/udp${NC}"
    ufw allow 8080/tcp comment 'AegisFlow Web UI & REST API'
    ufw allow 2055/udp comment 'AegisFlow NetFlow v5'
    ufw allow 2056/udp comment 'AegisFlow NetFlow v9'
    ufw allow 4739/udp comment 'AegisFlow IPFIX'
    ufw allow 6343/udp comment 'AegisFlow sFlow'
elif command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
    echo -e "${YELLOW}[*] Opening Firewalld ports: 8080/tcp, 2055/udp, 2056/udp, 4739/udp, 6343/udp${NC}"
    firewall-cmd --permanent --add-port=8080/tcp
    firewall-cmd --permanent --add-port=2055/udp
    firewall-cmd --permanent --add-port=2056/udp
    firewall-cmd --permanent --add-port=4739/udp
    firewall-cmd --permanent --add-port=6343/udp
    firewall-cmd --reload
fi

echo -e "${GREEN}[*] Step 8: Installing and starting systemd service...${NC}"
cp "${INSTALL_DIR}/deploy/aegisflow.service" /etc/systemd/system/aegisflow.service
systemctl daemon-reload
systemctl enable aegisflow.service
systemctl restart aegisflow.service

echo -e "${GREEN}[*] Waiting for AegisFlow engine to initialize...${NC}"
sleep 5

if curl -s http://127.0.0.1:8080/api/v1/health | grep -q "HEALTHY"; then
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${GREEN}  ✓ AegisFlow successfully deployed and running!                     ${NC}"
    echo -e "${GREEN}  Web Dashboard: http://<server-ip>:8080                              ${NC}"
    echo -e "${GREEN}  API Documentation: http://<server-ip>:8080/docs                     ${NC}"
    echo -e "${GREEN}  Service status: systemctl status aegisflow.service                  ${NC}"
    echo -e "${GREEN}======================================================================${NC}"
else
    echo -e "${YELLOW}[!] AegisFlow started, but health check is taking longer than usual.${NC}"
    echo -e "${YELLOW}    Check logs with: journalctl -u aegisflow.service -f${NC}"
fi
