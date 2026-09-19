<#
.SYNOPSIS
    Simulate Kerberoasting discovery queries for lab validation.
.DESCRIPTION
    Uses standard PowerShell ActiveDirectory module to query SPNs (Service Principal Names)
    with RC4 encryption support, mimicking the enumeration phase of Kerberoasting.
#>

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Write-Host "[*] Enumerating SPN accounts with weak encryption support..." -ForegroundColor Cyan

try {
    $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, SamAccountName, PasswordLastSet
    foreach ($acc in $spnAccounts) {
        Write-Host "Found SPN: $($acc.SamAccountName) -> $($acc.ServicePrincipalName -join ', ')" -ForegroundColor Yellow
    }
    Write-Host "[+] Enumeration completed successfully. Check Security Event ID 4769 in Event Viewer." -ForegroundColor Green
} catch {
    Write-Warning "ActiveDirectory module not available or not domain-joined. Ensure this is run in a domain lab."
}
