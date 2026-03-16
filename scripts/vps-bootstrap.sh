#!/usr/bin/env bash
# ============================================================
# vps-bootstrap.sh
#
# Run this script ONCE on a fresh Ubuntu/Debian VPS to:
#   1. Install Docker, docker-compose-plugin, ufw, fail2ban
#   2. Configure UFW firewall rules
#   3. Configure fail2ban SSH jail
#   4. Create the deployment directory structure
#   5. Generate cryptographic secrets
#
# Usage (on the VPS):
#   chmod +x scripts/vps-bootstrap.sh
#   sudo bash scripts/vps-bootstrap.sh
# ============================================================
set -euo pipefail

DEPLOY_DIR="/opt/sso-identity-hub"

echo "============================================================"
echo " SSO Identity Hub — VPS Bootstrap"
echo "============================================================"

# ---- 1. System update + dependency install -----------------
echo "[1/5] Installing system packages..."
apt-get update -y
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    ufw \
    fail2ban \
    git \
    htop \
    unzip

# Install Docker (official repo)
if ! command -v docker &>/dev/null; then
    echo "    Installing Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    echo "[+] Docker installed: $(docker --version)"
else
    echo "[+] Docker already present: $(docker --version)"
fi

# ---- 2. Firewall --------------------------------------------
echo "[2/5] Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP - ACME challenge + redirect'
ufw allow 443/tcp  comment 'HTTPS'
ufw allow 443/udp  comment 'HTTP/3 QUIC'
ufw --force enable
ufw status verbose

# ---- 3. fail2ban --------------------------------------------
echo "[3/5] Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled  = true
port     = ssh
maxretry = 5
bantime  = 3600
findtime = 600
EOF
systemctl enable --now fail2ban
echo "[+] fail2ban configured."

# ---- 4. Deployment directory --------------------------------
echo "[4/5] Setting up deployment directory at ${DEPLOY_DIR}..."
mkdir -p "${DEPLOY_DIR}"
mkdir -p "${DEPLOY_DIR}/secrets"
chmod 700 "${DEPLOY_DIR}/secrets"
mkdir -p /opt/backups
echo "[+] Directories created."

# ---- 5. Generate secrets ------------------------------------
echo "[5/5] Generating cryptographic secrets..."
cd "${DEPLOY_DIR}"
if [ -f "scripts/generate-secrets.sh" ]; then
    chmod +x scripts/generate-secrets.sh
    bash scripts/generate-secrets.sh
else
    echo "[!] generate-secrets.sh not found. Run it manually after transferring the repo."
fi

echo ""
echo "============================================================"
echo " Bootstrap complete."
echo ""
echo " NEXT STEPS:"
echo "  1. cat ${DEPLOY_DIR}/secrets/generated.env"
echo "  2. Copy values into ${DEPLOY_DIR}/.env"
echo "  3. Fill in CASDOOR, AZURE, SCIM values in .env"
echo "  4. Edit casdoor_conf/app.conf with DB credentials"
echo "  5. Run: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
echo "============================================================"
