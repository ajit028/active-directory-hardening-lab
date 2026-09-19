# Lab Topology & Environment Setup Guide

**Project:** Active Directory Security Auditing & Hardening Lab  
**Author:** Ajit Nayak ([ajit028.github.io](https://ajit028.github.io))

---

## 🏗️ Lab Architecture Overview

```
Network: 10.0.0.0/24 (Internal Lab — NAT/Host-Only)
Gateway: 10.0.0.1

┌─────────────────────────────────────────────────────────┐
│  DC01   │ Windows Server 2019 │ 10.0.0.10  │ Static IP  │
│  WS01   │ Windows 10 Pro      │ 10.0.0.20  │ DHCP       │
│  KALI   │ Kali Linux 2024.x   │ 10.0.0.99  │ Static IP  │
└─────────────────────────────────────────────────────────┘

SIEM Platform Options:
  - Microsoft Sentinel (Azure Log Analytics Workspace)
  - Splunk Free Trial (8 GB/day)
```

---

## ⚙️ 1. Windows Server 2019 — Domain Controller Setup

### 1.1 VM Specifications
- CPU: 2 vCPUs
- RAM: 4 GB
- Disk: 60 GB (thin provisioned)
- Network: Host-Only or Internal (do NOT bridge to attacker network directly unless intentional)
- ISO: Windows Server 2019 Evaluation (from Microsoft Evaluation Center)

### 1.2 Initial Setup (Post-Install, Before AD DS)

```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.0.0.10 -PrefixLength 24 -DefaultGateway 10.0.0.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1, 8.8.8.8

# Rename the machine
Rename-Computer -NewName "DC01" -Restart
```

### 1.3 Install AD DS & Promote to Domain Controller

```powershell
# Install RSAT + AD DS role
Install-WindowsFeature -Name AD-Domain-Services, GPMC, RSAT-ADDS -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetbiosName "CORP" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!Lab2024" -AsPlainText -Force) `
    -InstallDns `
    -Force
```

### 1.4 Create Lab Users and SPNs (for Kerberoasting / AS-REP Lab)

```powershell
Import-Module ActiveDirectory

# Create vulnerable lab accounts
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "svc-web" -SamAccountName "svc-web" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "svc-backup" -SamAccountName "svc-backup" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) -Enabled $true

# Register SPNs (enables Kerberoasting simulation)
setspn -A MSSQLSvc/sql01.corp.local:1433 svc-sql
setspn -A HTTP/web01.corp.local svc-web
setspn -A BACKUP/backup01.corp.local:8000 svc-backup

# Create AS-REP Roastable account (DONT_REQ_PREAUTH)
New-ADUser -Name "nopreauth-user" -SamAccountName "nopreauth-user" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl -Identity "nopreauth-user" -DoesNotRequirePreAuth $true
```

---

## 🖥️ 2. Windows 10 Pro — Domain Client Setup (WS01)

### 2.1 VM Specifications
- CPU: 2 vCPUs
- RAM: 4 GB
- Disk: 40 GB
- Network: Same internal/host-only network as DC01

### 2.2 Join to Domain

```powershell
# Set DNS to point to DC01
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.10

# Join domain
Add-Computer -DomainName "corp.local" -Credential (Get-Credential CORP\Administrator) -Restart
```

### 2.3 Enable WinRM for Remote Management

```powershell
# Run as Administrator
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.*"
```

---

## 🐉 3. Kali Linux — Attacker Machine Setup

### 3.1 VM Specifications
- CPU: 2 vCPUs
- RAM: 4 GB
- Disk: 40 GB
- Network: Internal (10.0.0.99)

### 3.2 Static IP Configuration

```bash
sudo ip addr add 10.0.0.99/24 dev eth0
sudo ip route add default via 10.0.0.1
echo "nameserver 10.0.0.10" | sudo tee /etc/resolv.conf
```

### 3.3 Install Red Team Tooling

```bash
# Update package lists
sudo apt-get update -y

# Impacket suite (DCSync, Kerberoasting, Pass-the-Hash)
pip3 install impacket

# BloodHound Python collector
pip3 install bloodhound

# CrackMapExec
sudo apt-get install crackmapexec -y

# Hashcat for offline cracking
sudo apt-get install hashcat -y
```

### 3.4 Verify Domain Connectivity

```bash
# Kerberos time sync is critical (.conf for Kali ↔ corp.local)
sudo cp /etc/krb5.conf /etc/krb5.conf.bak
cat <<EOF | sudo tee /etc/krb5.conf
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    CORP.LOCAL = {
        kdc = 10.0.0.10
        admin_server = 10.0.0.10
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
EOF

# Test DNS resolution
nslookup dc01.corp.local 10.0.0.10
```

---

## 📡 4. Sysmon Installation and Configuration

### 4.1 Download Sysmon and SwiftOnSecurity Config

```powershell
# Run on DC01 and WS01
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon\"

# Use SwiftOnSecurity's production Sysmon config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\sysmon-config.xml"

# Install Sysmon with config
.\Sysmon64.exe -accepteula -i "C:\Tools\sysmon-config.xml"
```

### 4.2 Verify Sysmon is Running

```powershell
Get-Service -Name "Sysmon64"
# Should show: Status = Running

# Verify Sysmon events (check Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-Table TimeCreated, Id, Message -Wrap
```

---

## 📤 5. Log Forwarding to SIEM

### 5.1 Microsoft Sentinel (Azure)

```powershell
# Install Azure Monitoring Agent (AMA) on DC01 and WS01
Invoke-WebRequest -Uri "https://aka.ms/InstallAzureMonitorAgent" -OutFile "C:\Tools\AMAInstall.ps1"
.\AMAInstall.ps1 -WorkspaceId "<YOUR_LOG_ANALYTICS_WORKSPACE_ID>" -WorkspaceKey "<YOUR_KEY>"
```

Configure a **Data Collection Rule (DCR)** in Azure Portal to collect:
- Windows Security Event Log (EventIDs: 4624, 4625, 4768, 4769, 4662, 4672)
- Microsoft-Windows-Sysmon/Operational (EventIDs: 1, 3, 7, 10, 11)

### 5.2 Splunk Universal Forwarder (Alternative)

```powershell
# Install Splunk UF on DC01 / WS01
msiexec /i "splunkforwarder-9.x-x64.msi" AGREETOLICENSE=Yes DEPLOYMENT_SERVER="10.0.0.50:8089" /quiet

# After install, configure inputs.conf
$inputsConf = @"
[WinEventLog://Security]
disabled = 0
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
"@
$inputsConf | Out-File -FilePath "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
Restart-Service SplunkForwarder
```

---

## ✅ Lab Verification Checklist

- [ ] DC01 resolves `corp.local` DNS records for all lab hosts
- [ ] WS01 is domain-joined and shows in `Active Directory Users and Computers`
- [ ] Kali can ping DC01 and do `kinit` against `CORP.LOCAL` Kerberos realm
- [ ] Event ID 4769 events appear in Security Event Log when TGS is requested
- [ ] Sysmon is running and logging Process Create (Event 1) events
- [ ] Logs are flowing to SIEM (query `| where TimeGenerated > ago(5m)` in Sentinel)
- [ ] KQL detection rule for Kerberoasting fires when simulation script runs
