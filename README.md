<p align="center">
  <img src="https://img.shields.io/badge/Platform-Active%20Directory-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Active Directory"/>
  <img src="https://img.shields.io/badge/Language-PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell"/>
  <img src="https://img.shields.io/badge/Detection-KQL%20%7C%20SPL-00A4EF?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="KQL | SPL"/>
  <img src="https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-E34F26?style=for-the-badge&logo=shield&logoColor=white" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"/>
</p>

<h1 align="center">🛡️ Active Directory Security Auditing & Hardening Lab</h1>

<p align="center">
  <strong>A hands-on offensive + defensive lab environment for simulating real-world Active Directory attacks, building production-grade detection rules, and implementing enterprise hardening controls — mapped to MITRE ATT&CK.</strong>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> •
  <a href="#attack-simulations">Attack Simulations</a> •
  <a href="#detection-engineering">Detection Engineering</a> •
  <a href="#hardening">Hardening</a> •
  <a href="#mitre-attck-mapping">MITRE ATT&CK</a> •
  <a href="#lab-setup">Lab Setup</a>
</p>

---

## 📋 Overview

This project provides a **complete, reproducible Active Directory security lab** designed for security professionals and aspiring SOC analysts. It covers the full attack lifecycle — from initial reconnaissance through credential theft to detection and response — with production-quality artifacts at every stage.

**What makes this different:**
- Real PowerShell attack simulations that generate authentic Windows Event Log telemetry
- Detection rules written in both **KQL** (Microsoft Sentinel) and **SPL** (Splunk) — ready to deploy
- Hardening scripts that implement CIS Benchmark and Microsoft security baselines
- Full MITRE ATT&CK mapping with technique IDs and detection coverage matrix

---

## 🏗️ Architecture {#architecture}

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LAB NETWORK — 10.0.0.0/24                          │
│                                                                           │
│  ┌─────────────────────┐    ┌─────────────────────┐                       │
│  │   DOMAIN CONTROLLER │    │   WINDOWS 10 CLIENT │                       │
│  │   DC01 (10.0.0.10)  │    │   WS01 (10.0.0.20)  │                       │
│  │                     │    │                     │                       │
│  │  • Windows Server   │◄──►│  • Domain-joined    │                       │
│  │    2019             │    │  • Sysmon installed  │                       │
│  │  • AD DS, DNS, DHCP │    │  • Standard user +   │                       │
│  │  • Advanced Audit   │    │    local admin       │                       │
│  │    Policies enabled │    │  • WinRM enabled     │                       │
│  │  • Sysmon + WEF     │    │                     │                       │
│  └────────┬────────────┘    └──────────┬──────────┘                       │
│           │                            │                                  │
│           │     ┌──────────────────┐   │                                  │
│           │     │  SIEM / SENTINEL │   │                                  │
│           ├────►│  (10.0.0.50)     │◄──┘                                  │
│           │     │                  │                                      │
│           │     │  • Log Analytics │          ┌─────────────────────┐     │
│           │     │    Workspace     │          │   ATTACKER MACHINE  │     │
│           │     │  • KQL Rules     │          │   KALI (10.0.0.99) │     │
│           │     │  • Sentinel      │          │                     │     │
│           │     │    Workbooks     │          │  • Impacket         │     │
│           │     └──────────────────┘          │  • Rubeus           │     │
│           │                                   │  • BloodHound       │     │
│           │                                   │  • CrackMapExec     │     │
│           └───────────────────────────────────┤  • Mimikatz         │     │
│                                               └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────┐
  │  LOG FLOW:  DC01/WS01 → Windows Event Forwarding → SIEM (Sentinel)     │
  │  TELEMETRY: Sysmon (Process, Network, Registry) + Security Event Log   │
  │  DETECTION: KQL analytics rules + Splunk correlation searches          │
  └──────────────────────────────────────────────────────────────────────────┘
```

---

## ⚔️ Attack Simulations {#attack-simulations}

### 1. Kerberoasting (`attacks/kerberoasting-sim.ps1`)

Simulates a **Kerberoasting** attack by enumerating Service Principal Name (SPN) accounts and requesting Kerberos TGS tickets using RC4 encryption — the tickets can then be cracked offline. This script generates **Event ID 4769** telemetry that feeds directly into the detection rules.

```powershell
# Enumerate SPN accounts → Request TGS tickets → Generate 4769 events
.\attacks\kerberoasting-sim.ps1 -Verbose
```

**What the attacker gains:** Offline-crackable service account password hashes  
**Detection signal:** Spike in 4769 events with RC4 (0x17) encryption type from a single source

### 2. AS-REP Roasting (`attacks/asrep-roasting-sim.ps1`)

Targets accounts with **Kerberos Pre-Authentication disabled** (`DONT_REQ_PREAUTH`). The script requests AS-REP responses containing the user's encrypted timestamp — crackable offline without any authentication.

```powershell
# Find vulnerable accounts → Extract AS-REP hashes → Generate 4768 events
.\attacks\asrep-roasting-sim.ps1 -Verbose
```

**What the attacker gains:** Password hashes for accounts with weak Kerberos config  
**Detection signal:** Event 4768 with PreAuth Type 0 (no pre-authentication)

### 3. BloodHound Attack Path Analysis (`attacks/bloodhound-guide.md`)

Step-by-step guide for running **SharpHound** collection, ingesting data into **BloodHound**, and identifying critical attack paths:
- Shortest path to Domain Admin
- Kerberoastable user paths
- Unconstrained delegation abuse
- ACL-based privilege escalation chains

---

## 🔍 Detection Engineering {#detection-engineering}

Production-ready detection rules in two SIEM platforms:

| Detection Rule | KQL (Sentinel) | SPL (Splunk) | Event ID | MITRE Technique |
|---|---|---|---|---|
| Kerberoasting (RC4 TGS) | ✅ | ✅ | 4769 | T1558.003 |
| AS-REP Roasting | ✅ | ✅ | 4768 | T1558.004 |
| Abnormal TGS Volume | ✅ | ✅ | 4769 | T1558.003 |
| Golden Ticket | ✅ | ✅ | 4769 | T1558.001 |
| DCSync | ✅ | ✅ | 4662 | T1003.006 |

### Sample KQL — Kerberoasting Detection

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"   // RC4
| where ServiceName !endswith "$"        // Exclude machine accounts
| summarize RequestCount = count(), TargetServices = make_set(ServiceName)
    by IpAddress, Account, bin(TimeGenerated, 5m)
| where RequestCount > 3
```

---

## 🔒 Hardening Controls {#hardening}

### GPO Hardening Script (`hardening/gpo-hardening.ps1`)

Automated Group Policy hardening implementing:

| Control | Setting | Why It Matters |
|---|---|---|
| Kerberos Encryption | AES-256 only, RC4 disabled | Prevents offline cracking of TGS tickets |
| LSASS Protection | RunAsPPL enabled | Blocks credential dumping (Mimikatz) |
| Password Policy | 14+ chars, complexity, 24 history | Reduces brute-force and spray attack surface |
| Account Lockout | 5 attempts / 30 min lockout | Limits password guessing |
| NTLM Restriction | Deny all in domain | Forces Kerberos, eliminates relay attacks |
| Audit Policies | 4624/4625/4768/4769 enabled | Ensures detection visibility |

### Security Audit Checklist (`hardening/audit-checklist.md`)

A 60+ item checklist covering password policy, privileged accounts, SPN hygiene, delegation review, trust relationships, and GPO baseline validation.

---

## 🎯 MITRE ATT&CK Mapping {#mitre-attck-mapping}

| Technique ID | Technique Name | Tactic | Lab Coverage |
|---|---|---|---|
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access | Attack sim + KQL + SPL + Hardening + **IR Playbook** |
| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Credential Access | Attack sim + KQL + SPL + Hardening |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Golden Ticket | Credential Access | Detection rules + **IR Playbook** |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | DCSync | Credential Access | Detection rules + **DCSync Simulation** + **IR Playbook** |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account Discovery | Discovery | BloodHound guide |
| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups Discovery | Discovery | BloodHound guide |
| [T1136.002](https://attack.mitre.org/techniques/T1136/002/) | Account Creation | Persistence | **IR Playbook** |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Privilege Escalation | **IR Playbook** + **SIEM Dashboard** |

---

## 🛡️ Incident Response Playbooks {#incident-response-playbooks}

When a security incident occurs, fast triage and structured response are critical. This repository now includes a comprehensive Incident Response playbook for Active Directory compromises.

### 📋 Kerberoasting & DCSync IR Playbook (`playbooks/ad-compromise-ir.md`)

A complete guide covering:
- **Kerberoasting Triage**: Detecting Event ID 4769 RC4 requests, KQL threat-hunting queries, containment & remediation steps (password rotation, migration to gMSA).
- **DCSync Triage**: Detecting Event ID 4662 with replication rights, isolating compromised hosts, ACL audits, and `krbtgt` double-reset procedures.
- **Tier Administration Model**: Strict Tier 0 / Tier 1 / Tier 2 separation with Privileged Access Workstation (PAW) requirements and cross-tier access controls.
- **Forest Recovery & DC Restoration**: Non-authoritative vs. authoritative restores, rebuilding the PDC Emulator, lingering object cleanup, and integrity verification.

---

### 🖥️ DCSync Simulation & Detection Guide (`scripts/simulate-dcsync.ps1`)

A PowerShell script to audit Active Directory for DCSync permissions and simulate replication rights discovery:
- Discovers non-standard principals holding `Replicating Directory Changes` / `Replicating Directory Changes All` rights.
- Generates SOC-ready alerting guidance and SIEM query examples (Splunk / Sentinel).
- Audits Domain object ACLs for replication threats (MITRE ATT&CK T1003.006).

---

### 📊 Enterprise SIEM Dashboard (`dashboards/ad-security-dashboard.json`)

A Splunk Dashboard Studio JSON template for visualizing Active Directory security telemetry:
- **Real-time metrics**: Kerberoasting attempts, DCSync events, account creations, and ACL modifications.
- **Risk heatmaps**: Event frequency over time and tiered risk scores for Tier 0/1/2 assets.
- **High-risk account tables**: Top accounts with multiple permission changes.
- **Automated 5-minute refresh** with configurable time windows.



## 🛠️ Technologies {#technologies}

| Category | Tools & Platforms |
|---|---|
| **Identity** | Active Directory Domain Services, Kerberos, Group Policy |
| **Attack Tooling** | Rubeus, Impacket, BloodHound, SharpHound, Mimikatz |
| **SIEM / Detection** | Microsoft Sentinel (KQL), Splunk (SPL) |
| **Endpoint Telemetry** | Sysmon, Windows Event Forwarding, Security Event Log |
| **Scripting** | PowerShell 5.1+, Python 3 |
| **Virtualization** | VirtualBox / Hyper-V / VMware |
| **Standards** | MITRE ATT&CK, CIS Benchmarks, Microsoft Security Baselines |

---

## 📁 Repository Structure

```
active-directory-hardening-lab/
├── attacks/
│   ├── kerberoasting-sim.ps1       # Kerberoasting attack simulation
│   ├── asrep-roasting-sim.ps1      # AS-REP roasting attack simulation
│   └── bloodhound-guide.md         # BloodHound attack path walkthrough
├── hardening/
│   ├── gpo-hardening.ps1           # Automated GPO hardening script
│   └── audit-checklist.md          # 60+ item AD security audit checklist
├── detection/
│   ├── kql-detections.kql          # Microsoft Sentinel KQL detection rules
│   └── splunk-detections.spl       # Splunk SPL detection queries
├── lab-setup/
│   └── lab-topology.md             # Complete lab environment build guide
├── playbooks/
│   └── ad-compromise-ir.md         # AD Incident Response playbook (Kerberoasting, DCSync, Tier Admin, Forest Recovery)
├── dashboards/
│   └── ad-security-dashboard.json  # Splunk Dashboard Studio JSON template
├── scripts/
│   ├── audit-ad.ps1                # Enterprise AD security audit script
│   └── simulate-dcsync.ps1         # DCSync permissions discovery & alerting guide
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🛡️ Enterprise-Grade Auditing & Automation
This repository now features advanced automated security auditing, production-ready Sigma detections, and integrated CI/CD for validation.

### 📊 Automated AD Security Auditing (`scripts/audit-ad.ps1`)
A comprehensive PowerShell script to audit your AD environment.
- **Inspects**: Domain functional levels, password policies, unconstrained delegation, admin-count objects, and dangerous ACLs.
- **Output**: Generates a professional HTML security report and a JSON data file for SIEM ingest.
- **Usage**: `.\scripts\audit-ad.ps1 -ReportPath .\AuditReport.html`

### 🕵️♂️ Detection Engineering (Sigma Rules)
Standardized production-ready Sigma rules to detect common AD attacks:
- **Kerberoasting**: `detection/sigma-rules/kerberoasting.yml` (Event ID 4769)
- **AS-REP Roasting**: `detection/sigma-rules/asrep-roasting.yml` (Event ID 4768)

### ⚙️ Security CI/CD Automation (`.github/workflows/ad-audit-ci.yml`)
Automated validation for every push/PR:
- **Linting**: Runs `PSScriptAnalyzer` against all PowerShell scripts.
- **Validation**: Ensures KQL and YAML (Sigma rules) syntax correctness.

---

## 🚀 Getting Started

### Prerequisites

- Windows Server 2019 (or later) ISO for Domain Controller
- Windows 10/11 Pro ISO for client machine
- Kali Linux ISO (or any Debian-based distro)
- Hypervisor: Hyper-V, VirtualBox, or VMware Workstation
- 16 GB RAM minimum (32 GB recommended)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/ajit028/active-directory-hardening-lab.git
cd active-directory-hardening-lab

# Follow the lab setup guide
# → lab-setup/lab-topology.md

# Run attack simulations (from domain-joined machine)
.\attacks\kerberoasting-sim.ps1 -Verbose

# Apply hardening controls (from Domain Controller)
.\hardening\gpo-hardening.ps1

# Deploy detection rules to your SIEM
# → detection/kql-detections.kql (Sentinel)
# → detection/splunk-detections.spl (Splunk)
```

---

## ⚠️ Disclaimer

This project is intended for **authorized security testing and educational purposes only**. All attack simulations must be conducted in isolated lab environments. Unauthorized use of these techniques against systems you do not own or have explicit permission to test is illegal and unethical.

---

## 👤 Author

**Ajit Nayak**

- 🌐 Portfolio: [ajit028.github.io](https://ajit028.github.io)
- 💼 LinkedIn: [linkedin.com/in/ajit028](https://linkedin.com/in/ajit028)
- 🐙 GitHub: [github.com/ajit028](https://github.com/ajit028)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
