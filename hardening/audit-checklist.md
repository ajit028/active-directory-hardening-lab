# Active Directory Security Audit & Hardening Checklist

**Target Identity Platform:** Microsoft Active Directory Domain Services (AD DS)  
**Author:** Ajit Nayak ([ajit028.github.io](https://ajit028.github.io))  
**Framework Alignment:** MITRE ATT&CK, CIS Microsoft Windows Server Benchmarks

Use this checklist during a Red Team engagement, Blue Team audit, or as a post-deployment verification for the hardening lab.

---

## 1. Password Policy & Authentication Hygiene

- [ ] **Default Domain Password Policy Setup**
  - Minimum length is at least 14 characters (CIS recommendation).
  - Password history remembers at least 24 passwords.
  - Max password age is 90 days.
  - Password complexity is enabled.
- [ ] **Account Lockout Policy**
  - Lockout threshold is 5 invalid attempts.
  - Lockout duration is 30 minutes (or Administrator reset only).
  - Reset lockout counter after 30 minutes.
- [ ] **Fine-Grained Password Policies (FGPP)**
  - `Domain Admins`/Tier 0 accounts require 20+ character passwords.
  - Service accounts (if not gMSA) require 25+ character passwords.
- [ ] **NTLM Restriction**
  - `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers` set to Audit or Deny All.
  - SMB Signing is enforced (`Digitally sign communications (Always)`) to prevent NTLM Relay.
- [ ] **Kerberos Encryption**
  - `Network security: Configure encryption types allowed for Kerberos` set to AES-128 and AES-256 ONLY (RC4 / DES disabled).
  - Service Principal Names (SPNs) support AES-256 encryption.

## 2. Privileged Account Hardening (Tier 0)

- [ ] **Tiered Administration Model**
  - The `Protected Users` security group is used for highly privileged accounts (prevents NTLM authentication, disables unconstrained delegation).
  - Domain Admin credentials are NEVER used to interactive sign-in or RDP into Tier 2 (workstations) or Tier 1 (member servers).
- [ ] **Built-in Administrator**
  - Built-in Local Administrator Password Solution (Windows LAPS) is deployed across all endpoints and servers.
  - Domain built-in Administrator account `SID-500` is renamed and has a random, 64-character password, stored securely.
- [ ] **Service Accounts**
  - No human user accounts have SPNs configured.
  - Use Group Managed Service Accounts (gMSA) globally where applications support them (eliminates Kerberoasting risks).

## 3. Delegation & Trust Relationship Audit

- [ ] **Unconstrained Delegation**
  - Audit AD for `TRUSTED_FOR_DELEGATION` (Unconstrained Delegation). Only Domain Controllers should have this flag.
  - Disable unconstrained delegation for all member servers.
- [ ] **Constrained & RBCD Delegation**
  - Identify protocol transition flags (Any Authentication Protocol).
  - Ensure Resource-Based Constrained Delegation (RBCD) permissions do not have overly permissive `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- [ ] **Trusts**
  - External and Forest trusts use **Selective Authentication** instead of Forest-Wide Authentication.
  - SID History auditing is enabled on trust creation.

## 4. Privilege Escalation & Lateral Movement Prevention

- [ ] **Local Admin Access**
  - Domain groups like `Domain Users` or `Authenticated Users` are NOT in the local Administrators group on endpoints.
- [ ] **RunAsPPL & Credential Guard**
  - LSA Protection (Protected Process Light) is enabled on all domain controllers and high-value servers (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`).
  - Windows Defender Credential Guard is enabled.
- [ ] **WMI / WinRM Protection**
  - WinRM (PowerShell Remoting) access is restricted by Group Policy to specific admin jump servers, not `*`.

## 5. Pre-Authentication Misconfigurations

- [ ] **AS-REP Roasting Audit**
  - Ensure zero active accounts have the `DONT_REQ_PREAUTH` UserAccountControl flag set.
  - Run powershell query: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}`

## 6. Access Control (BloodHound/ACL Review)

- [ ] Validate standard users do not have `GenericAll`, `WriteDacl`, `WriteOwner`, or `GenericWrite` on the Domain object, Domain Controllers OU, or Admin groups.
- [ ] Validate AdminSDHolder operates correctly (SDProp runs every 60m to protect privileged groups). Ensure no rogue accounts were injected into the AdminSDHolder ACL.

## 7. Advanced Audit & Telemetry Validation

- [ ] **Audit Policy (GPO Configuration)**
  - Logon/Logoff: Success/Failure for 4624 (Logon), 4625 (Failed Logon).
  - Account Logon: Success/Failure for 4768 (TGT), 4769 (TGS) — critical for Kerberoasting detection.
  - DS Access: Success/Failure for 4662 (Directory Service Access) — critical for DCSync detection.
  - Sensitive Privilege Use: Success/Failure for 4672 (Admin Logon).
- [ ] **Endpoint Visibility (Sysmon / EDR)**
  - Sysmon or Microsoft Defender for Endpoint is deployed to endpoints and Domain Controllers.
  - Event Forwarding (WEF) is shipping logs real-time to the SIEM.
