<#
.SYNOPSIS
    Enterprise Active Directory Security Audit & Hardening Assessment Script
.DESCRIPTION
    Inspects Active Directory domain functional levels, password policies, unconstrained delegation,
    admin count objects, and dangerous ACLs/permissions. Exports comprehensive HTML and JSON reports.
.AUTHOR
    Ajit Nayak (Active Directory Hardening Lab)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = ".\AD-Security-Audit-Report.html",

    [Parameter(Mandatory=$false)]
    [string]$JsonPath = ".\AD-Security-Audit-Data.json"
)

# Ensure ActiveDirectory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required. Please run on a Domain Controller or a machine with RSAT-AD-PowerShell installed."
    exit 1
}

Import-Module ActiveDirectory

Write-Host "[*] Starting Active Directory Security Audit..." -ForegroundColor Cyan

$AuditResults = [PSCustomObject]@{
    DomainInfo          = $null
    PasswordPolicy      = $null
    FGPP                = @()
    Unconstrained       = @()
    AdminCountObjects   = @()
    DangerousACLs       = @()
    Timestamp           = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

# 1. Domain Information & Functional Level
try {
    Write-Host "[+] Collecting Domain Functional Level and Information..." -ForegroundColor Yellow
    $Domain = Get-ADDomain
    $Forest = Get-ADForest
    $AuditResults.DomainInfo = [PSCustomObject]@{
        NetBIOSName             = $Domain.NetBIOSName
        DNSName                 = $Domain.DNSName
        DomainFunctionalLevel   = $Domain.DomainFunctionalLevel
        ForestFunctionalLevel   = $Forest.ForestFunctionalLevel
        PDCEmulator             = $Domain.PDCEmulator
        InfrastructureMaster    = $Domain.InfrastructureMaster
        SchemaMaster            = $Domain.SchemaMaster
    }
} catch {
    Write-Warning "Could not retrieve Domain information: $_"
}

# 2. Default Domain Password Policy & FGPP
try {
    Write-Host "[+] Analyzing Password Policies & FGPP..." -ForegroundColor Yellow
    $DefaultDomainPassPolicy = Get-ADDefaultDomainPasswordPolicy
    $AuditResults.PasswordPolicy = [PSCustomObject]@{
        ComplexityEnabled       = $DefaultDomainPassPolicy.ComplexityEnabled
        MinPasswordLength       = $DefaultDomainPassPolicy.MinPasswordLength
        MaxPasswordAge          = $DefaultDomainPassPolicy.MaxPasswordAge
        PasswordHistoryCount    = $DefaultDomainPassPolicy.PasswordHistoryCount
        LockoutThreshold        = $DefaultDomainPassPolicy.LockoutThreshold
        LockoutDuration         = $DefaultDomainPassPolicy.LockoutDuration
    }

    $FGPP = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
    foreach ($policy in $FGPP) {
        $AuditResults.FGPP += [PSCustomObject]@{
            Name                    = $policy.Name
            Precedence              = $policy.Precedence
            MinPasswordLength       = $policy.MinPasswordLength
            ComplexityEnabled       = $policy.ComplexityEnabled
            LockoutThreshold        = $policy.LockoutThreshold
        }
    }
} catch {
    Write-Warning "Could not retrieve Password Policies: $_"
}

# 3. Unconstrained Delegation
try {
    Write-Host "[+] Scanning for Unconstrained Delegation..." -ForegroundColor Yellow
    $UnconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, OperatingSystem
    $UnconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

    foreach ($comp in $UnconstrainedComputers) {
        $AuditResults.Unconstrained += [PSCustomObject]@{
            Name        = $comp.Name
            ObjectClass = "Computer"
            OS          = $comp.OperatingSystem
            DistinguishedName = $comp.DistinguishedName
        }
    }
    foreach ($usr in $UnconstrainedUsers) {
        $AuditResults.Unconstrained += [PSCustomObject]@{
            Name        = $usr.SamAccountName
            ObjectClass = "User"
            OS          = "N/A"
            DistinguishedName = $usr.DistinguishedName
        }
    }
} catch {
    Write-Warning "Could not scan Unconstrained Delegation: $_"
}

# 4. AdminCount Objects (Protected Accounts)
try {
    Write-Host "[+] Auditing Privileged Objects (adminCount = 1)..." -ForegroundColor Yellow
    $AdminObjects = Get-ADObject -LDAPFilter "(adminCount=1)" -Properties sAMAccountName, objectClass, lastLogonDate, whenCreated
    foreach ($obj in $AdminObjects) {
        $AuditResults.AdminCountObjects += [PSCustomObject]@{
            Name              = $obj.Name
            Class             = $obj.objectClass
            DistinguishedName = $obj.DistinguishedName
            WhenCreated       = $obj.whenCreated
        }
    }
} catch {
    Write-Warning "Could not audit AdminCount objects: $_"
}

# 5. Dangerous ACLs / Permissions (Basic heuristic scan for GenericAll/WriteDacl on sensitive groups/users)
try {
    Write-Host "[+] Scanning for Dangerous ACLs on Sensitive Objects..." -ForegroundColor Yellow
    $SensitiveDNs = @(
        (Get-ADGroup "Domain Admins").DistinguishedName,
        (Get-ADGroup "Administrators").DistinguishedName,
        "CN=Domain Controllers,CN=Configuration,$((Get-ADDomain).DistinguishedName)"
    )

    foreach ($dn in $SensitiveDNs) {
        if ($dn) {
            $Acl = Get-Acl "AD:\$dn"
            foreach ($Access in $Acl.Access) {
                if ($Access.AccessControlType -eq 'Allow' -and ($Access.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|FullControl')) {
                    # Filter out built-in SYSTEM, Administrators, etc.
                    if ($Access.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN|SELF') {
                        $AuditResults.DangerousACLs += [PSCustomObject]@{
                            TargetObject  = $dn
                            Principal     = $Access.IdentityReference.Value
                            Rights        = $Access.ActiveDirectoryRights.ToString()
                            Inheritance   = $Access.InheritanceType
                        }
                    }
                }
            }
        }
    }
} catch {
    Write-Warning "Could not fully scan ACLs: $_"
}

# Export JSON
$AuditResults | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8
Write-Host "[+] JSON report saved to $JsonPath" -ForegroundColor Green

# Generate HTML Report
$HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Active Directory Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1 { color: #005a9e; border-bottom: 2px solid #005a9e; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 20px; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; }
        th { background-color: #f1f3f5; color: #495057; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .meta { font-size: 0.9em; color: #6c757d; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; background: #e2e3e5; color: #383d41; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
<div class="container">
    <h1>Active Directory Security Audit Report</h1>
    <div class="meta">Generated on: $($AuditResults.Timestamp) | Domain: $($AuditResults.DomainInfo.DNSName)</div>

    <h2>Domain Information</h2>
    <table>
        <tr><th>NetBIOS Name</th><td>$($AuditResults.DomainInfo.NetBIOSName)</td></tr>
        <tr><th>DNS Name</th><td>$($AuditResults.DomainInfo.DNSName)</td></tr>
        <tr><th>Domain Functional Level</th><td>$($AuditResults.DomainInfo.DomainFunctionalLevel)</td></tr>
        <tr><th>PDC Emulator</th><td>$($AuditResults.DomainInfo.PDCEmulator)</td></tr>
    </table>

    <h2>Password Policy</h2>
    <table>
        <tr><th>Complexity Enabled</th><td>$($AuditResults.PasswordPolicy.ComplexityEnabled)</td></tr>
        <tr><th>Min Password Length</th><td>$($AuditResults.PasswordPolicy.MinPasswordLength)</td></tr>
        <tr><th>Max Password Age (Days)</th><td>$([Math]::Round($AuditResults.PasswordPolicy.MaxPasswordAge.Days, 1))</td></tr>
        <tr><th>Account Lockout Threshold</th><td>$($AuditResults.PasswordPolicy.LockoutThreshold)</td></tr>
    </table>

    <h2>Unconstrained Delegation Objects</h2>
    <table>
        <tr><th>Name</th><th>Object Class</th><th>Operating System</th><th>Distinguished Name</th></tr>
        $(([string[]](foreach ($u in $AuditResults.Unconstrained) { "<tr><td>$($u.Name)</td><td>$($u.ObjectClass)</td><td>$($u.OS)</td><td>$($u.DistinguishedName)</td></tr>" })) -join "`n")
    </table>

    <h2>Privileged Objects (adminCount = 1)</h2>
    <table>
        <tr><th>Name</th><th>Class</th><th>Distinguished Name</th><th>When Created</th></tr>
        $(([string[]](foreach ($a in $AuditResults.AdminCountObjects) { "<tr><td>$($a.Name)</td><td>$($a.Class)</td><td>$($a.DistinguishedName)</td><td>$($a.WhenCreated)</td></tr>" })) -join "`n")
    </table>

    <h2>Dangerous ACLs on Sensitive Objects</h2>
    <table>
        <tr><th>Target Object</th><th>Principal</th><th>Rights</th><th>Inheritance</th></tr>
        $(([string[]](foreach ($d in $AuditResults.DangerousACLs) { "<tr><td>$($d.TargetObject)</td><td><span class='badge badge-danger'>$($d.Principal)</span></td><td>$($d.Rights)</td><td>$($d.Inheritance)</td></tr>" })) -join "`n")
    </table>
</div>
</body>
</html>
"@

Set-Content -Path $ReportPath -Value $HtmlContent -Encoding UTF8
Write-Host "[+] HTML Security Audit Report saved to $ReportPath" -ForegroundColor Green
