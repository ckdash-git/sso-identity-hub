<#
.SYNOPSIS
    Configures Microsoft Entra ID (Azure AD) domain federation to trust
    a Casdoor SAML 2.0 Identity Provider instance.

.DESCRIPTION
    This script:
      1. Installs and imports the Microsoft.Graph PowerShell module if missing.
      2. Connects to Microsoft Graph with the required admin scopes.
      3. Verifies the target domain exists and is currently managed.
      4. Creates (or replaces) a federation configuration pointing to Casdoor.
      5. Converts the domain authentication type from Managed to Federated.

    PREREQUISITES
    -------------
    - PowerShell 7.2+ (runs on Windows, macOS, Linux).
    - A Global Administrator or Hybrid Identity Administrator account in
      the Entra ID tenant.
    - The domain (e.g., contoso.com) must already be verified in Entra ID
      (Admin Center > Settings > Domain names).
    - Casdoor must be deployed and the SAML application must be created
      *before* running this script so that you have:
        a) The Casdoor SAML SSO URL        (CASDOOR_SAML_SSO_URL)
        b) The Casdoor SAML SLO URL        (CASDOOR_SAML_SLO_URL)
        c) The Casdoor X.509 signing cert  (CASDOOR_SIGNING_CERT_B64)

    HOW TO RUN
    ----------
    # One-time execution policy unlock (run as Administrator on Windows)
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    # Dry-run (shows what would be configured, makes no changes)
    .\configure-entra-federation.ps1 -WhatIf

    # Live run
    .\configure-entra-federation.ps1

.NOTES
    Reversibility: To revert a domain to Managed authentication:
        Update-MgDomain -DomainId "contoso.com" -AuthenticationType "Managed"
        Remove-MgDomainFederationConfiguration -DomainId "contoso.com" `
            -InternalDomainFederationId "<federation-id>"
#>

[CmdletBinding(SupportsShouldProcess)]
param()

# ============================================================
# SECTION 1 — CONFIGURATION
# Replace every variable below before running.
# ============================================================

# The verified domain in your Entra ID tenant to federate.
# This is the domain suffix of the users who will authenticate via Casdoor.
# Example: "contoso.com"
$FEDERATED_DOMAIN = "YOUR_ENTRA_VERIFIED_DOMAIN"   # e.g. contoso.com

# Casdoor SAML Entity ID / Issuer URI.
# In Casdoor Admin > Applications > [Your App] > SAML tab > EntityID field.
# Default: the root URL of your Casdoor instance.
$CASDOOR_ISSUER_URI = "https://auth.cachatto.click"

# Casdoor SAML SSO (SingleSignOn) URL.
# In Casdoor Admin > Applications > [Your App] > SAML tab > SSO URL field.
$CASDOOR_SAML_SSO_URL = "https://auth.cachatto.click/api/saml/redirect?id=built-in/sso-identity-hub"

# Casdoor SAML SLO (SingleLogOut) URL.
$CASDOOR_SAML_SLO_URL = "https://auth.cachatto.click/api/saml/logout?id=built-in/sso-identity-hub"

# Casdoor X.509 signing certificate in base64 (DER format, NO PEM headers).
# How to obtain:
#   Casdoor Admin > Certificates > [Your Cert] > Certificate field
#   Copy the content BETWEEN "-----BEGIN CERTIFICATE-----" and
#   "-----END CERTIFICATE-----", remove all newlines, paste here.
$CASDOOR_SIGNING_CERT_B64 = "PASTE_BASE64_CERTIFICATE_HERE_NO_HEADERS_NO_NEWLINES"

# Display name shown in the Entra ID admin portal for this federation config.
$FEDERATION_DISPLAY_NAME = "Casdoor SSO Identity Hub"

# ============================================================
# SECTION 2 — MODULE INSTALLATION
# ============================================================

function Ensure-Module {
    param([string]$Name, [string]$MinVersion = "0.0")

    $installed = Get-Module -ListAvailable -Name $Name |
                 Where-Object { $_.Version -ge [version]$MinVersion } |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

    if (-not $installed) {
        Write-Host "[*] Installing module: $Name ..." -ForegroundColor Cyan
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Host "[+] Module present: $Name v$($installed.Version)" -ForegroundColor Green
    }
}

Ensure-Module -Name "Microsoft.Graph.Identity.DirectoryManagement" -MinVersion "2.0"

Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

# ============================================================
# SECTION 3 — AUTHENTICATION
# Required Graph permissions:
#   Domain.ReadWrite.All  — read domain objects and write federation config
#   Organization.Read.All — read tenant info for validation
# ============================================================

Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph `
    -Scopes "Domain.ReadWrite.All", "Organization.Read.All" `
    -NoWelcome

$context = Get-MgContext
Write-Host "[+] Authenticated as: $($context.Account) in tenant: $($context.TenantId)" -ForegroundColor Green

# ============================================================
# SECTION 4 — PRE-FLIGHT VALIDATION
# ============================================================

Write-Host "[*] Validating domain: $FEDERATED_DOMAIN ..." -ForegroundColor Cyan

try {
    $domain = Get-MgDomain -DomainId $FEDERATED_DOMAIN -ErrorAction Stop
} catch {
    Write-Error "Domain '$FEDERATED_DOMAIN' not found in tenant '$($context.TenantId)'. Verify it in Entra Admin Center first."
    Disconnect-MgGraph | Out-Null
    exit 1
}

if (-not $domain.IsVerified) {
    Write-Error "Domain '$FEDERATED_DOMAIN' is not yet verified. Complete DNS verification before federating."
    Disconnect-MgGraph | Out-Null
    exit 1
}

if ($domain.AuthenticationType -eq "Federated") {
    Write-Warning "Domain '$FEDERATED_DOMAIN' is already Federated. Existing federation config will be replaced."

    # Retrieve any existing federation config IDs so we can remove them
    $existingConfigs = Get-MgDomainFederationConfiguration -DomainId $FEDERATED_DOMAIN -ErrorAction SilentlyContinue
    foreach ($cfg in $existingConfigs) {
        Write-Host "[*] Removing existing federation config: $($cfg.Id) ..."
        if ($PSCmdlet.ShouldProcess($FEDERATED_DOMAIN, "Remove existing federation config $($cfg.Id)")) {
            Remove-MgDomainFederationConfiguration `
                -DomainId $FEDERATED_DOMAIN `
                -InternalDomainFederationId $cfg.Id
        }
    }
}

# ============================================================
# SECTION 5 — CREATE FEDERATION CONFIGURATION
# ============================================================

Write-Host "[*] Creating federation configuration for '$FEDERATED_DOMAIN'..." -ForegroundColor Cyan

$federationParams = @{
    DisplayName                       = $FEDERATION_DISPLAY_NAME
    IssuerUri                         = $CASDOOR_ISSUER_URI
    PassiveSignInUri                  = $CASDOOR_SAML_SSO_URL
    SignOutUri                        = $CASDOOR_SAML_SLO_URL
    SigningCertificate                = $CASDOOR_SIGNING_CERT_B64
    PreferredAuthenticationProtocol   = "saml"
    # FederatedIdpMfaBehavior controls MFA behaviour when the external IdP
    # claims MFA was already performed.
    # "acceptIfMfaDoneByFederatedIdp" = trust Casdoor's MFA claim
    # "enforceMfaByFederatedIdp"      = always require MFA (Casdoor handles it)
    # "rejectMfaByFederatedIdp"       = Entra always re-challenges MFA
    FederatedIdpMfaBehavior           = "acceptIfMfaDoneByFederatedIdp"
}

if ($PSCmdlet.ShouldProcess($FEDERATED_DOMAIN, "New-MgDomainFederationConfiguration")) {
    $newConfig = New-MgDomainFederationConfiguration `
        -DomainId $FEDERATED_DOMAIN `
        -BodyParameter $federationParams

    Write-Host "[+] Federation configuration created. ID: $($newConfig.Id)" -ForegroundColor Green
}

# ============================================================
# SECTION 6 — FLIP DOMAIN TO FEDERATED AUTHENTICATION
# ============================================================

Write-Host "[*] Setting domain authentication type to Federated..." -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess($FEDERATED_DOMAIN, "Update-MgDomain AuthenticationType=Federated")) {
    Update-MgDomain `
        -DomainId $FEDERATED_DOMAIN `
        -AuthenticationType "Federated"

    Write-Host "[+] Domain '$FEDERATED_DOMAIN' is now Federated." -ForegroundColor Green
}

# ============================================================
# SECTION 7 — VERIFICATION OUTPUT
# ============================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host " FEDERATION CONFIGURATION SUMMARY" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host " Federated Domain     : $FEDERATED_DOMAIN"
Write-Host " Issuer URI           : $CASDOOR_ISSUER_URI"
Write-Host " SSO (Passive) URI    : $CASDOOR_SAML_SSO_URL"
Write-Host " SLO URI              : $CASDOOR_SAML_SLO_URL"
Write-Host " Auth Protocol        : SAML 2.0"
Write-Host " MFA Behaviour        : acceptIfMfaDoneByFederatedIdp"
Write-Host "================================================================"
Write-Host ""
Write-Host " NEXT STEPS:"
Write-Host "  1. In Casdoor Admin > Applications > [Your App] > SAML:"
Write-Host "     - Add Entra ID as an SP with Entity ID:"
Write-Host "       urn:federation:MicrosoftOnline"
Write-Host "     - Set ACS URL (Assertion Consumer Service):"
Write-Host "       https://login.microsoftonline.com/login.srf"
Write-Host "  2. Test with: https://login.microsoftonline.com/?whr=$FEDERATED_DOMAIN"
Write-Host "  3. Sign in with a user in the federated domain."
Write-Host ""

Disconnect-MgGraph | Out-Null
Write-Host "[+] Disconnected from Microsoft Graph." -ForegroundColor Green
