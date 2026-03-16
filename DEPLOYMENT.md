# SSO Identity Hub — Production Deployment Guide

## Variable Reference

Throughout this document, replace the following placeholders. Never commit
actual values to git.

| Placeholder              | Example value              | Description                            |
|--------------------------|----------------------------|----------------------------------------|
| `cachatto.click`            | `acme-sso.io`              | DNS domain you control                 |
| `YOUR_LOCAL_REPO`        | `~/Desktop/SSO-Identity-Hub-Server` | Path on your local machine    |
| `YOUR_EMAIL`             | `ops@acme-sso.io`          | Let's Encrypt contact email            |
| `YOUR_POSTGRES_PASSWORD` | *(output of generate-secrets.sh)* | DB password               |
| `YOUR_SCIM_BEARER_TOKEN` | *(output of generate-secrets.sh)* | SCIM API token            |
| `YOUR_CASDOOR_SECRET`    | *(created in Casdoor admin)*      | Casdoor app client secret |
| `YOUR_AZURE_TENANT_ID`   | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Entra ID tenant GUID   |
| `YOUR_AZURE_CLIENT_ID`   | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Entra ID app client ID |
| `YOUR_AZURE_SECRET`      | *(Azure portal secret value)*     | Entra ID app secret    |
| `YOUR_ENTRA_DOMAIN`      | `contoso.com`              | Verified domain to federate in Entra   |

---

## Part 1 — VPS Hardening and Repository Transfer

### 1.1 Lock Down the VPS (Run Immediately)

Connect to the VPS once using the current credentials, then immediately lock
it down. After step 4 you will only be able to log in with your SSH key.

```bash
# On your LOCAL machine — generate an SSH key pair if you do not have one
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/sso_vps_ed25519 -C "sso-vps-deploy"

# Copy your public key to the VPS (using the temporary password)
ssh-copy-id -i ~/.ssh/sso_vps_ed25519.pub root@31.97.61.182

# Now log in with the key
ssh -i ~/.ssh/sso_vps_ed25519 root@31.97.61.182
```

On the VPS, harden the SSH daemon:

```bash
# Change root password to a strong random passphrase
passwd

# Edit sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config

# Validate config before restarting
sshd -t && systemctl restart sshd
```

Configure the host firewall:

```bash
apt-get update -y && apt-get install -y ufw

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (Let's Encrypt ACME challenge + redirect)
ufw allow 443/tcp   # HTTPS
ufw allow 443/udp   # HTTP/3 QUIC
ufw --force enable
ufw status verbose
```

Install runtime dependencies:

```bash
apt-get install -y \
    docker.io \
    docker-compose-plugin \
    git \
    curl \
    htop \
    fail2ban

# Enable Docker daemon
systemctl enable --now docker

# Add bantime to SSH jail
cat >> /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled  = true
port     = ssh
maxretry = 5
bantime  = 3600
findtime = 600
EOF
systemctl enable --now fail2ban
```

### 1.2 Prepare the Deployment Directory

```bash
# On the VPS
mkdir -p /opt/sso-identity-hub
cd /opt/sso-identity-hub
```

### 1.3 Transfer the Repository

**Option A — rsync (recommended for first deploy)**

```bash
# On your LOCAL machine
rsync -avz \
    --exclude='.git' \
    --exclude='secrets/' \
    --exclude='*.env' \
    -e "ssh -i ~/.ssh/sso_vps_ed25519" \
    YOUR_LOCAL_REPO/ \
    root@31.97.61.182:/opt/sso-identity-hub/
```

**Option B — git (recommended for subsequent deploys)**

```bash
# On the VPS — clone directly from your remote
cd /opt/sso-identity-hub
git clone https://github.com/YOUR_ORG/sso-identity-hub.git .
# For private repos, use a deploy key:
#   ssh-keygen -t ed25519 -f /root/.ssh/deploy_key -N ""
#   Add /root/.ssh/deploy_key.pub as a read-only deploy key in GitHub
#   git clone git@github.com:YOUR_ORG/sso-identity-hub.git .
```

### 1.4 Add .gitignore Entries

Ensure secrets and env files are never committed:

```bash
# On the VPS
cat >> /opt/sso-identity-hub/.gitignore <<'EOF'
secrets/
.env
casdoor_conf/*.conf
EOF
```

---

## Part 2 — Pre-Flight: DNS and Secrets

### 2.1 DNS Records

Add these A records with your DNS registrar before starting Caddy.
Caddy's ACME HTTP-01 challenge requires port 80 to be reachable.

| Record type | Hostname             | Value              |
|-------------|----------------------|--------------------|
| A           | `auth.cachatto.click`   | `31.97.61.182`     |
| A           | `hub.cachatto.click`    | `31.97.61.182`     |
| A           | `cachatto.click`        | `31.97.61.182`     |

Wait for propagation (`dig auth.cachatto.click` must return `31.97.61.182`).

### 2.2 Generate Cryptographic Secrets

```bash
cd /opt/sso-identity-hub
chmod +x scripts/generate-secrets.sh
./scripts/generate-secrets.sh

# Review the output
cat secrets/generated.env
```

### 2.3 Configure the Production .env

```bash
cp .env.example .env
chmod 600 .env
nano .env          # or vim .env
```

Set these values (minimum required for a working deployment):

```dotenv
SERVER_ENV=production

POSTGRES_HOST=postgres
POSTGRES_USER=sso_user
POSTGRES_PASSWORD=YOUR_POSTGRES_PASSWORD       # from secrets/generated.env
POSTGRES_DB=sso_identity_hub
POSTGRES_SSLMODE=disable                       # TLS terminated at Caddy

CASDOOR_ENDPOINT=https://auth.cachatto.click
CASDOOR_CLIENT_ID=YOUR_CASDOOR_CLIENT_ID
CASDOOR_CLIENT_SECRET=YOUR_CASDOOR_SECRET
CASDOOR_ORGANIZATION_NAME=built-in
CASDOOR_APPLICATION_NAME=sso-identity-hub

OIDC_ISSUER_URL=https://auth.cachatto.click
OIDC_REDIRECT_URI=https://hub.cachatto.click/auth/callback

JWT_RS256_PRIVATE_KEY_PATH=/secrets/rsa_private.pem
JWT_RS256_PUBLIC_KEY_PATH=/secrets/rsa_public.pem
JWT_KEY_ID=sso-hub-key-2026-v1

TOKEN_MAX_AGE_SECONDS=28800

SCIM_BEARER_TOKEN=YOUR_SCIM_BEARER_TOKEN       # from secrets/generated.env

MSGRAPH_TENANT_ID=YOUR_AZURE_TENANT_ID
MSGRAPH_CLIENT_ID=YOUR_AZURE_CLIENT_ID
MSGRAPH_CLIENT_SECRET=YOUR_AZURE_SECRET

LOG_FORMAT=json
LOG_LEVEL=info
```

### 2.4 Configure casdoor_conf/app.conf

```bash
nano /opt/sso-identity-hub/casdoor_conf/app.conf
```

Replace every `YOUR_*` placeholder:
- `YOUR_POSTGRES_USER` -> `sso_user`
- `YOUR_POSTGRES_PASSWORD` -> the password from `secrets/generated.env`
- `YOUR_POSTGRES_DB` -> `sso_identity_hub`
- `cachatto.click` -> your actual domain

### 2.5 Configure Caddyfile

```bash
nano /opt/sso-identity-hub/Caddyfile
```

Replace all instances of `cachatto.click` with your actual domain.
Also add your email for Let's Encrypt by prepending the following block:

```caddyfile
{
    email YOUR_EMAIL
    # Uncomment the next line to test against Let's Encrypt staging first
    # acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```

---

## Part 3 — Run in Production Daemon Mode

```bash
cd /opt/sso-identity-hub

# Build the Go binary and pull all images
docker compose \
    -f docker-compose.yml \
    -f docker-compose.prod.yml \
    build --no-cache

# Start all services as daemons
docker compose \
    -f docker-compose.yml \
    -f docker-compose.prod.yml \
    up -d

# Verify all containers are running (healthy)
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Expected output (all State=running):

```
NAME             IMAGE                    COMMAND       SERVICE      STATUS
sso_caddy        caddy:2-alpine           ...           caddy        running
sso_casdoor      casbin/casdoor:latest    ...           casdoor      running
sso_postgres     postgres:16-alpine       ...           postgres     running (healthy)
sso_server       sso-identity-hub-...     ...           sso-server   running
```

### 3.1 Useful Operational Commands

```bash
# Tail live logs from all containers
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f

# Tail a single service
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f sso_server

# Restart a single service after a config change
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart sso_server

# Zero-downtime redeploy (rebuild image, then rolling replace)
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d --build --no-deps sso-server

# Stop everything (preserves volumes)
docker compose -f docker-compose.yml -f docker-compose.prod.yml down

# Nuke everything including volumes (DESTRUCTIVE — data loss)
# docker compose -f docker-compose.yml -f docker-compose.prod.yml down -v
```

### 3.2 Create a Systemd Unit for Auto-Start on Reboot

```bash
cat > /etc/systemd/system/sso-identity-hub.service <<'EOF'
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
EOF

systemctl daemon-reload
systemctl enable sso-identity-hub
systemctl start sso-identity-hub
```

### 3.3 Verify TLS

```bash
curl -I https://auth.cachatto.click/
# Expect: HTTP/2 200, strict-transport-security header present

curl -I https://hub.cachatto.click/health
# Expect: HTTP/2 200
```

---

## Part 4 — Casdoor Initial Configuration

After the stack is running, complete the Casdoor initial setup via the web UI
at `https://auth.cachatto.click`.

**Step 1 — Admin account**
On first access, Casdoor redirects to the setup wizard. Create the admin
account with a strong password.

**Step 2 — Create the SAML/OIDC Application**
Navigate to Admin > Applications > Add.

| Field               | Value                                                        |
|---------------------|--------------------------------------------------------------|
| Name                | `sso-identity-hub`                                           |
| Organization        | `built-in`                                                   |
| Display name        | `SSO Identity Hub`                                           |
| Homepage URL        | `https://hub.cachatto.click`                                    |
| Redirect URL        | `https://hub.cachatto.click/auth/callback`                      |
| Logout redirect URL | `https://hub.cachatto.click/auth/logout`                        |
| Grant types         | Authorization Code                                           |
| Response types      | code                                                         |
| PKCE                | Enabled, S256 only                                           |

After saving, copy the generated **Client ID** and **Client Secret** into `.env`
as `CASDOOR_CLIENT_ID` and `CASDOOR_CLIENT_SECRET`.

**Step 3 — Create a Certificate for SAML Signing**
Navigate to Admin > Certificates > Add.

| Field        | Value                                      |
|--------------|--------------------------------------------|
| Name         | `sso-hub-saml-cert`                        |
| Scope        | `JWT` (covers both OIDC and SAML signing)  |
| Type         | `x509`                                     |
| Bit size     | `2048` minimum, `4096` recommended         |
| Expire years | `5`                                        |

Click Generate. After generation, click the certificate name and copy the
**Certificate** field content (PEM). This is needed for both Entra ID and
Google Workspace federation scripts.

Assign this certificate to your application under:
Admin > Applications > sso-identity-hub > Cert field.

---

## Part 5 — Microsoft Entra ID Federation

### 5.1 Register an App Registration (for MS Graph Revocation)

This app registration is used by the SSO Hub to call
`/v1.0/users/{id}/revokeSignInSessions` (hard-revoke on logout).

1. Entra Admin Center (`https://entra.microsoft.com`) > App Registrations > New registration
2. Name: `SSO Identity Hub Graph Client`
3. Supported account type: `Accounts in this organizational directory only`
4. Redirect URI: leave blank
5. Register

After registration:
- Note the **Application (client) ID** → `MSGRAPH_CLIENT_ID` in `.env`
- Note the **Directory (tenant) ID** → `MSGRAPH_TENANT_ID` in `.env`
- Certificates & secrets > New client secret → `MSGRAPH_CLIENT_SECRET` in `.env`
- API Permissions > Add > Microsoft Graph > Application permissions:
  - `User.RevokeSessions.All`
  - `AuditLog.Read.All` (optional, for session audit)
- Grant admin consent

### 5.2 Configure Casdoor as SAML IdP for Entra ID Domain Federation

This federates an entire Entra ID verified domain to Casdoor, meaning users
with email addresses in that domain will authenticate via Casdoor's SAML
endpoint rather than Azure AD's native login page.

**Before running the script:**

a) In Casdoor Admin > Applications > sso-identity-hub > SAML tab, note:
   - **SSO URL**: typically `https://auth.cachatto.click/api/saml/redirect?id=built-in/sso-identity-hub`
   - **SLO URL**: typically `https://auth.cachatto.click/api/saml/logout?id=built-in/sso-identity-hub`
   - **Entity ID**: `https://auth.cachatto.click`

b) Copy the certificate from Admin > Certificates > sso-hub-saml-cert.
   Remove the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
   headers and ALL newlines — the result is a single base64 string.

c) Edit the script:

```bash
nano /opt/sso-identity-hub/scripts/configure-entra-federation.ps1
```

Fill in:
- `$FEDERATED_DOMAIN` = your verified Entra domain (e.g., `contoso.com`)
- `$CASDOOR_ISSUER_URI` = `https://auth.cachatto.click`
- `$CASDOOR_SAML_SSO_URL` = Casdoor SSO URL from step (a)
- `$CASDOOR_SAML_SLO_URL` = Casdoor SLO URL from step (a)
- `$CASDOOR_SIGNING_CERT_B64` = single-line base64 certificate from step (b)

**Run the script:**

```powershell
# Install PowerShell 7 if not present
# Windows: winget install Microsoft.PowerShell
# macOS:   brew install --cask powershell
# Linux:   https://docs.microsoft.com/powershell/scripting/install/installing-powershell-on-linux

# Dry-run first — confirms what will be configured, makes NO changes
pwsh ./scripts/configure-entra-federation.ps1 -WhatIf

# Live run
pwsh ./scripts/configure-entra-federation.ps1
```

The script will open a browser for interactive authentication. Sign in with
a **Global Administrator** or **Hybrid Identity Administrator** account.

**Test the federation:**

```
https://login.microsoftonline.com/?whr=YOUR_ENTRA_DOMAIN
```

You should be redirected to Casdoor's login page.

### 5.3 Add Entra ID as SAML Service Provider in Casdoor

After the PowerShell script runs, register Entra ID as an SP inside Casdoor:

Navigate to Casdoor Admin > Applications > sso-identity-hub > SAML:

| Field              | Value                                                              |
|--------------------|--------------------------------------------------------------------|
| SP Entity ID       | `urn:federation:MicrosoftOnline`                                   |
| ACS URL            | `https://login.microsoftonline.com/login.srf`                      |
| Name ID format     | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`           |
| Attribute mapping  | Add: `IDPEmail` -> user's email attribute in Casdoor user store    |

Save and click "Download SP Metadata" to verify the configuration.

---

## Part 6 — Google Workspace Federation

Google Workspace supports SAML 2.0 SSO via "Third-Party IdP" profiles.
Casdoor acts as the IdP; Google Workspace is the SP.

### 6.1 Prerequisites

- Google Workspace Admin Console access (`admin.google.com`)
- Super Admin role
- Casdoor SAML endpoints and certificate from Part 4 Step 3

### 6.2 Register Google Workspace as SAML SP in Casdoor

First, create dedicated SAML application in Casdoor for Google Workspace:

1. Casdoor Admin > Applications > Add

| Field               | Value                                             |
|---------------------|---------------------------------------------------|
| Name                | `google-workspace`                                |
| Organization        | `built-in`                                        |
| Display name        | `Google Workspace`                                |
| Enable SAML         | Yes                                               |

2. In the SAML tab of this application:

| Field              | Value                                                              |
|--------------------|--------------------------------------------------------------------|
| SP Entity ID       | `google.com/a/YOUR_GOOGLE_DOMAIN`                                  |
| ACS URL            | `https://www.google.com/a/YOUR_GOOGLE_DOMAIN/acs`                  |
| Name ID format     | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`           |
| Name ID value      | User email address (maps to Casdoor's `email` attribute)            |

Note the resulting:
- **SSO URL** (IdP-initiated): shown in the SAML tab after saving
- **Entity ID (Issuer)**: `https://auth.cachatto.click`

### 6.3 Google Workspace Admin Console — Step-by-Step

**Path**: `admin.google.com` > Security > Authentication >
SSO with third-party IdP

Step 1 — Click "Add SSO profile" (top right of the page).

Step 2 — Set Profile name: `Casdoor SSO Identity Hub`

Step 3 — Toggle "Set up SSO with third-party identity provider" to ON.

Step 4 — Fill in the IdP configuration fields:

| Field               | Value                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------|
| Sign-in page URL    | `https://auth.cachatto.click/api/saml/redirect?id=built-in/google-workspace`                     |
| Sign-out page URL   | `https://auth.cachatto.click/api/saml/logout?id=built-in/google-workspace`                       |
| Change password URL | `https://auth.cachatto.click/user/password/change`                                                |
| Verification certificate | Upload the PEM file from Casdoor Admin > Certificates > sso-hub-saml-cert > Download  |

Step 5 — Under "Domain-specific service URLs":
- Select "Automatically redirect users to the third-party IdP sign-in page"
- This forces all users to authenticate via Casdoor.

Step 6 — Click Save.

Step 7 — Assign the SSO profile to an Organizational Unit (OU) for testing:
- Directory > Organizational Units > Select a test OU
- Security > SSO with third-party IdP > select the "Casdoor SSO Identity Hub" profile
- Apply to users in this OU only at first

Step 8 — Verify SAML attribute mappings:

Navigate to the SSO profile > Attribute Mapping:

| Google Workspace attribute | Casdoor SAML assertion attribute |
|---------------------------|----------------------------------|
| `email`                   | `email`                          |
| `firstName`               | `given_name`                     |
| `lastName`                | `family_name`                    |

Step 9 — Test:
Open a browser in Incognito mode, navigate to:
`https://accounts.google.com/AccountChooser?Email=testuser@YOUR_GOOGLE_DOMAIN`

You should be redirected to `https://auth.cachatto.click` for authentication.

After successful authentication you should land in Gmail (or whichever
Google service you navigated to).

---

## Part 7 — Ongoing Operations

### Log Rotation

Caddy logs are configured with rolling file appender in the Caddyfile.
Docker container logs use `json-file` driver with `max-size=50m, max-file=5`.

### Certificate Renewal

Caddy renews Let's Encrypt certificates automatically (60 days before expiry).
No manual intervention is required.

### Database Backups

```bash
# On the VPS — run daily via cron
docker exec sso_postgres \
    pg_dump -U sso_user sso_identity_hub \
    | gzip > /opt/backups/sso_$(date +%Y%m%d_%H%M%S).sql.gz

# Rotate: keep last 30 daily backups
find /opt/backups -name 'sso_*.sql.gz' -mtime +30 -delete
```

Add to crontab (`crontab -e`):

```cron
0 3 * * * docker exec sso_postgres pg_dump -U sso_user sso_identity_hub | gzip > /opt/backups/sso_$(date +\%Y\%m\%d_\%H\%M\%S).sql.gz && find /opt/backups -name 'sso_*.sql.gz' -mtime +30 -delete
```

### Updating the Stack

```bash
cd /opt/sso-identity-hub
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d --build --no-deps sso-server
```
