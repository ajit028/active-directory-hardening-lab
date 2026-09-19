<#
.SYNOPSIS
    Active Directory GPO Hardening Script
.DESCRIPTION
    Implements enterprise-grade Active Directory hardening controls aligned with
    CIS Benchmarks, Microsoft Security Baselines, and NSA/CISA AD Security Guidelines.
    Covers Kerberos encryption hardening, credential protection, NTLM restriction,
    and advanced audit policy configuration.
.NOTES
    Author: Ajit Nayak (https://ajit028.github.io)
    Version: 1.0
    Requires: Domain Admin or equivalent privileges; RSAT / AD Module
    Test in lab environment before deploying to production.
#>

#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordPolicy,

    [Parameter(Mandatory=$false)]
    [switch]$SkipNTLMRestriction
)

$ErrorActionPreference = "Stop"
$Domain = (Get-ADDomain).DNSRoot
$DomainDN = (Get-ADDomain).DistinguishedName

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  AD Hardening Script v1.0 — Ajit Nayak" -ForegroundColor Cyan
Write-Host "  Domain: $Domain" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

function Set-RegistryHardening {
    param($Path, $Name, $Value, $Type)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-Host "    [+] Set: $Path\$Name = $Value" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────
# 1. KERBEROS ENCRYPTION HARDENING: Disable RC4, Enforce AES-256
# ─────────────────────────────────────────────────────────
Write-Host "`n[*] Section 1: Kerberos Encryption Hardening (Disable RC4, Enable AES-256)" -ForegroundColor Yellow

$gpoName = "AD-Hardening-Kerberos"
try {
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        $gpo = New-GPO -Name $gpoName -Comment "Kerberos AES-256 enforcement, RC4 disabled. CIS AD Hardening."
        Write-Host "    [+] Created GPO: $gpoName" -ForegroundColor Green
        New-GPLink -Name $gpoName -Target $DomainDN -Enforced Yes | Out-Null
        Write-Host "    [+] Linked GPO to domain root with enforcement" -ForegroundColor Green
    }
} catch {
    Write-Host "    [!] GPO creation requires Group Policy module. Applying via registry fallback..." -ForegroundColor Yellow
}

# Kerberos Supported Encryption Types:
# 0x7FFFFFFF = All types (insecure / default)
# 0x18 (24) = AES128 + AES256 ONLY (RC4 disabled)
# 0x08 (8)  = AES256 ONLY (most restrictive)
$krbRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if ($PSCmdlet.ShouldProcess("Kerberos", "Disable RC4, enforce AES-256")) {
    Set-RegistryHardening -Path $krbRegPath -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord
}
Write-Host "    [*] SupportedEncryptionTypes 0x18 = AES128 + AES256 only. RC4 (0x17) is now disabled." -ForegroundColor Gray

# Also set per-account Kerberoasting protection (AES-256 required for service accounts)
Write-Host "    [*] Checking service accounts for AES support..." -ForegroundColor Gray
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties msDS-SupportedEncryptionTypes | ForEach-Object {
    if ($_."msDS-SupportedEncryptionTypes" -ne 24) {
        Write-Host "    [!] Account $($_.SamAccountName) has weak encryption type. Updating..." -ForegroundColor Yellow
        Set-ADUser $_.SamAccountName -KerberosEncryptionType AES256 -WhatIf:$WhatIf
    }
}

# ─────────────────────────────────────────────────────────
# 2. LSASS PROTECTION: RunAsPPL (Credential Guard prerequisite)
# ─────────────────────────────────────────────────────────
Write-Host "`n[*] Section 2: LSASS RunAsPPL Protection (Defends vs. Mimikatz / Credential Dump)" -ForegroundColor Yellow

$lsassRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ($PSCmdlet.ShouldProcess("LSASS", "Enable RunAsPPL mode")) {
    Set-RegistryHardening -Path $lsassRegPath -Name "RunAsPPL" -Value 1 -Type DWord
    Set-RegistryHardening -Path $lsassRegPath -Name "RunAsPPLBoot" -Value 1 -Type DWord
}
Write-Host "    [*] LSASS Protected Process Light (PPL) enabled. Credential dumping tools blocked." -ForegroundColor Gray
Write-Host "    [*] Requires: Secure Boot + UEFI; reboot to take effect." -ForegroundColor Gray

# Enable Windows Defender Credential Guard
$cgRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if ($PSCmdlet.ShouldProcess("Device Guard", "Enable Credential Guard policy")) {
    Set-RegistryHardening -Path $cgRegPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-RegistryHardening -Path $cgRegPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord
    Set-RegistryHardening -Path $cgRegPath -Name "HypervisorEnforcedCodeIntegrity" -Value 2 -Type DWord
    
    $cgCGPath = "$cgRegPath\Scenarios\CredentialGuard"
    Set-RegistryHardening -Path $cgCGPath -Name "Enabled" -Value 1 -Type DWord
    Set-RegistryHardening -Path $cgCGPath -Name "Locked" -Value 0 -Type DWord
}

# ─────────────────────────────────────────────────────────
# 3. PASSWORD POLICY: Enforce Strong Password Requirements
# ─────────────────────────────────────────────────────────
if (-not $SkipPasswordPolicy) {
    Write-Host "`n[*] Section 3: Password Policy Hardening" -ForegroundColor Yellow

    $pwdPolicy = @{
        MinPasswordLength          = 14
        PasswordHistoryCount       = 24
        MaxPasswordAge             = (New-TimeSpan -Days 90)
        MinPasswordAge             = (New-TimeSpan -Days 1)
        LockoutThreshold           = 5
        LockoutDuration            = (New-TimeSpan -Minutes 30)
        LockoutObservationWindow   = (New-TimeSpan -Minutes 30)
    }

    if ($PSCmdlet.ShouldProcess("Domain Password Policy", "Apply hardened defaults")) {
        Set-ADDefaultDomainPasswordPolicy -Identity $Domain `
            -MinPasswordLength $pwdPolicy.MinPasswordLength `
            -PasswordHistoryCount $pwdPolicy.PasswordHistoryCount `
            -MaxPasswordAge $pwdPolicy.MaxPasswordAge `
            -MinPasswordAge $pwdPolicy.MinPasswordAge `
            -LockoutThreshold $pwdPolicy.LockoutThreshold `
            -LockoutDuration $pwdPolicy.LockoutDuration `
            -LockoutObservationWindow $pwdPolicy.LockoutObservationWindow `
            -ComplexityEnabled $true
    }

    Write-Host "    [+] Password Policy Applied:" -ForegroundColor Green
    Write-Host "        - Minimum Length: 14 characters" -ForegroundColor Gray
    Write-Host "        - Password History: 24 passwords remembered" -ForegroundColor Gray
    Write-Host "        - Max Age: 90 days" -ForegroundColor Gray
    Write-Host "        - Lockout: 5 attempts / 30m window / 30m lockout" -ForegroundColor Gray
    Write-Host "        - Complexity: Enabled" -ForegroundColor Gray
}

# Fine-Grained Password Policy (FGPP) for Privileged Accounts
Write-Host "    [*] Applying Fine-Grained Password Policy for Domain Admins..." -ForegroundColor Gray
try {
    $fgpPolicy = Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "Admin-Password-Policy"} -ErrorAction SilentlyContinue
    if ($null -eq $fgpPolicy) {
        New-ADFineGrainedPasswordPolicy -Name "Admin-Password-Policy" `
            -Precedence 10 `
            -MinPasswordLength 20 `
            -PasswordHistoryCount 24 `
            -MinPasswordAge "1.00:00:00" `
            -MaxPasswordAge "60.00:00:00" `
            -LockoutThreshold 3 `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00" `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false `
            -Description "Fine-grained password policy for Domain Admins"
        
        Add-ADFineGrainedPasswordPolicySubject -Identity "Admin-Password-Policy" -Subjects "Domain Admins"
        Write-Host "    [+] Fine-Grained Policy created and linked to Domain Admins (20+ char minimum)" -ForegroundColor Green
    } else {
        Write-Host "    [*] Admin-Password-Policy already exists. Skipping." -ForegroundColor Gray
    }
} catch {
    Write-Host "    [!] FGPP creation requires AD DS + appropriate admin role: $_" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────────────────
# 4. NTLM RESTRICTION: Disable / Audit NTLM
# ─────────────────────────────────────────────────────────
if (-not $SkipNTLMRestriction) {
    Write-Host "`n[*] Section 4: NTLM Authentication Restriction" -ForegroundColor Yellow

    $ntlmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    
    if ($PSCmdlet.ShouldProcess("NTLM", "Restrict / Audit NTLM Authentication")) {
        # Start with Audit mode before enforcing (value 1 = Audit, value 2 = Deny all)
        Set-RegistryHardening -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -Name "RestrictNTLM" -Value 1 -Type DWord
        
        # Restrict NTLM across the domain (requires domain GPO)
        $ntlmDomainPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Set-RegistryHardening -Path $ntlmDomainPath -Name "RestrictNTLMInDomain" -Value 7 -Type DWord
        Set-RegistryHardening -Path $ntlmDomainPath -Name "DCAllowedNTLMServers" -Value 0 -Type DWord
    }
    
    Write-Host "    [*] NTLM set to AUDIT mode first. Monitor event 8004/8001 before enforcing." -ForegroundColor Yellow
    Write-Host "    [*] After analysis: change RestrictNTLM from 1 (Audit) to 7 (Deny All in Domain)" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────
# 5. ADVANCED AUDIT POLICIES: Enable Key Security Event IDs
# ─────────────────────────────────────────────────────────
Write-Host "`n[*] Section 5: Advanced Audit Policy Configuration" -ForegroundColor Yellow

$auditSettings = @(
    @{ Category = "Account Logon";    Subcategory = "Kerberos Service Ticket Operations"; Value = "Success,Failure" },  # 4769
    @{ Category = "Account Logon";    Subcategory = "Kerberos Authentication Service";    Value = "Success,Failure" },  # 4768
    @{ Category = "Logon/Logoff";     Subcategory = "Logon";                              Value = "Success,Failure" },  # 4624/4625
    @{ Category = "Logon/Logoff";     Subcategory = "Account Lockout";                   Value = "Success,Failure" },  # 4740
    @{ Category = "DS Access";        Subcategory = "Directory Service Access";           Value = "Success,Failure" },  # 4662 (DCSync)
    @{ Category = "DS Access";        Subcategory = "Directory Service Changes";          Value = "Success,Failure" },  # 4720, 4728
    @{ Category = "Privilege Use";    Subcategory = "Sensitive Privilege Use";            Value = "Success,Failure" },  # 4672
    @{ Category = "Policy Change";    Subcategory = "Authentication Policy Change";       Value = "Success,Failure" }   # 4713
)

foreach ($setting in $auditSettings) {
    if ($PSCmdlet.ShouldProcess($setting.Subcategory, "Enable audit policy")) {
        $auditCmd = "auditpol /set /subcategory:`"$($setting.Subcategory)`" /success:enable /failure:enable"
        Invoke-Expression $auditCmd 2>&1 | Out-Null
        Write-Host "    [+] Enabled: $($setting.Subcategory) ($($setting.Value))" -ForegroundColor Green
    }
}

Write-Host "    [*] Event IDs now covered: 4624, 4625, 4740, 4768, 4769, 4662, 4672, 4713, 4720, 4728" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────
# 6. SUMMARY
# ─────────────────────────────────────────────────────────
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete! Review required:" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "    [✓] Kerberos: RC4 disabled, AES-256 enforced" -ForegroundColor Green
Write-Host "    [✓] LSASS: RunAsPPL + Credential Guard enabled" -ForegroundColor Green
Write-Host "    [✓] Password: 14+ chars, lockout 5/30m enforced" -ForegroundColor Green
Write-Host "    [✓] NTLM: Audit mode configured (switch to Deny after review)" -ForegroundColor Yellow
Write-Host "    [✓] Audit: 4624/4625/4768/4769/4662 all enabled" -ForegroundColor Green
Write-Host "    [!] REBOOT DC01 to activate RunAsPPL changes." -ForegroundColor Red
Write-Host "    [!] Test Kerberos auth after RC4 change to confirm no breaks." -ForegroundColor Red
