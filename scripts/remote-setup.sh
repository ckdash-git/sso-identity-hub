#!/usr/bin/env bash
# ============================================================
# remote-setup.sh
#
# Runs entirely on the VPS via:
#   ssh root@31.97.61.182 'bash -s' < scripts/remote-setup.sh
#
# What it does:
#   1. apt update + install Docker, ufw, fail2ban
#   2. Lock down firewall (22, 80, 443)
#   3. Configure fail2ban ssh jail
#   4. Create /opt/sso-identity-hub directory tree
#   5. Install systemd service unit
# ============================================================
set -euo pipefail

DEPLOY_DIR="/opt/sso-identity-hub"

echo "=== [1/5] Installing packages ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq

# Docker official repository
if ! command -v docker &>/dev/null; then
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
fi

apt-get install -y -qq ufw fail2ban git htop curl
echo "[+] Packages installed. Docker: $(docker --version)"

echo "=== [2/5] Configuring UFW ==="
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP ACME'
ufw allow 443/tcp  comment 'HTTPS'
ufw allow 443/udp  comment 'HTTP3'
ufw --force enable
echo "[+] UFW active."

echo "=== [3/5] Configuring fail2ban ==="
cat > /etc/fail2ban/jail.d/sshd.local <<'JAIL'
[sshd]
enabled  = true
port     = ssh
maxretry = 5
bantime  = 3600
findtime = 600
JAIL
systemctl enable --now fail2ban
echo "[+] fail2ban active."

echo "=== [4/5] Creating directory structure ==="
mkdir -p "${DEPLOY_DIR}/secrets"
mkdir -p "${DEPLOY_DIR}/casdoor_conf"
mkdir -p /opt/backups
chmod 700 "${DEPLOY_DIR}/secrets"
echo "[+] Directories created."

echo "=== [5/5] Installing systemd service ==="
cat > /etc/systemd/system/sso-identity-hub.service <<'UNIT'
[Unit]
Description=SSO Identity Hub Docker Compose Stack
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/sso-identity-hub
ExecStart=/usr/bin/docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.yml -f docker-compose.prod.yml down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable sso-identity-hub
echo "[+] Systemd unit installed."

echo ""
echo "============================================================"
echo " VPS bootstrap complete. Ready for file transfer."
echo "============================================================"
