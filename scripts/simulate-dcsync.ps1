<#
.SYNOPSIS
    Simulates DCSync Permissions Discovery and provides Active Directory security auditing and alerting guidance.
.DESCRIPTION
    This script inspects Active Directory naming contexts and domain root ACLs to discover security principals
    holding Directory Replication rights (Replicating Directory Changes / Replicating Directory Changes All).
    It helps Blue Teams and SOC analysts validate whether non-authorized users possess DCSync capabilities (MITRE ATT&CK T1003.006).
.AUTHOR
    Ajit Nayak (Active Directory Hardening Lab)
.NOTES
    Run in an Active Directory lab environment with RSAT-AD-PowerShell installed.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController = $env:LOGONSERVER -replace '\\', ''
)

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "       Active Directory DCSync Permissions Audit & Simulation        " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# Check ActiveDirectory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required. Install RSAT-AD-PowerShell."
    exit 1
}

Import-Module ActiveDirectory

try {
    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    Write-Host "[+] Target Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "[+] Domain DN: $domainDN" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Active Directory domain. Ensure this script is run on a domain-joined machine with proper privileges."
    exit 1
}

Write-Host "`n[i] Analyzing Domain Object ACLs for Replication Rights..." -ForegroundColor Yellow
Write-Host "[i] GUIDs of interest:" -ForegroundColor DarkGray
Write-Host "    - Replicating Directory Changes (11316f70-8bcf-11d1-a3f0-00aa0031c784)" -ForegroundColor DarkGray
Write-Host "    - Replicating Directory Changes All (11316f73-8bcf-11d1-a3f0-00aa0031c784)" -ForegroundColor DarkGray

$repGuid1 = [Guid]"11316f70-8bcf-11d1-a3f0-00aa0031c784"
$repGuid2 = [Guid]"11316f73-8bcf-11d1-a3f0-00aa0031c784"

try {
    $acl = Get-Acl "AD:\$domainDN"
    $accessRules = $acl.Access

    $suspiciousPrincipals = @()

    foreach ($rule in $accessRules) {
        if ($rule.ObjectType -eq $repGuid1 -or $rule.ObjectType -eq $repGuid2 -or $rule.ActiveDirectoryRights -match "Replicate") {
            $identity = $rule.IdentityReference.Value
            $rights = $rule.ActiveDirectoryRights
            $isInherited = $rule.IsInherited

            # Check if principal is a DC computer account or standard Domain Admins/Enterprise Admins
            if ($identity -notmatch "Domain Controllers\$" -notmatch "Enterprise Read-Only Domain Controllers\$" -notmatch "SYSTEM$") {
                $suspiciousPrincipals += [PSCustomObject]@{
                    Identity     = $identity
                    Rights       = $rights
                    ObjectType   = $rule.ObjectType
                    IsInherited  = $isInherited
                    AccessControlType = $rule.AccessControlType
                }
            }
        }
    }

    if ($suspiciousPrincipals.Count -gt 0) {
        Write-Host "`n[!] WARNING: Non-Standard Principals with Replication Rights Found!" -ForegroundColor Red
        $suspiciousPrincipals | Format-Table -AutoSize
    } else {
        Write-Host "`n[+] No unauthorized principal replication rights found on the domain root." -ForegroundColor Green
    }
}
catch {
    Write-Warning "Could not read domain ACLs directly: $_"
}

Write-Host "`n---------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " SOC Alerting & Detection Guidance for DCSync (MITRE ATT&CK T1003.006):" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "1. Security Event ID: 4662"
Write-Host "   - Look for Access Mask 0x100 and Extended Right GUIDs:"
     Write-Host "     11316f70-8bcf-11d1-a3f0-00aa0031c784" -ForegroundColor Gray
     Write-Host "     11316f73-8bcf-11d1-a3f0-00aa0031c784" -ForegroundColor Gray
Write-Host "2. SIEM Splunk KQL / Splunk Query Example:"
Write-Host '   index=windows EventCode=4662 (Properties="*11316f70-8bcf-11d1-a3f0-00aa0031c784*" OR Properties="*11316f73-8bcf-11d1-a3f0-00aa0031c784*")' -ForegroundColor DarkYellow
Write-Host "3. Mitigation & Remediation:"
Write-Host "   - Periodically audit ACLs using PowerView (Get-DomainObjectAcl -ResolveGUIDs)."
Write-Host "   - Ensure principle of least privilege is enforced across administrative accounts."
Write-Host "=====================================================================" -ForegroundColor Cyan
