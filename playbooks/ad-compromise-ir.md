# Active Directory Incident Response Playbook

## 1. Overview & Objectives
This playbook outlines the standardized Incident Response (IR) procedure for detecting, investigating, containing, eradicating, and recovering from Active Directory (AD) compromise scenarios, such as Kerberoasting, DCSync attacks, Golden/Silver tickets, and lateral movement across enterprise tiers.

### Scope & Target Audience
- **Target Audience:** Security Operations Center (SOC) Analysts, Incident Responders, AD Administrators, and Blue Team Engineers.
- **Scope:** On-premises Active Directory forests, Hybrid Azure AD / Entra ID identity synchronization paths, and connected tier administration boundaries.

---

## 2. MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Detection / Indicator |
| :--- | :--- | :--- | :--- |
| **Credential Access** | T1558.003 | Kerberoast | Event ID 4769 with RC4 encryption (`0x17`) or high ticket volume |
| **Credential Access** | T1003.006 | DCSync / DS-Replication | Event ID 4662 with replication rights (`DS-Replication-Get-Changes-All`) |
| **Persistence** | T1136.002 | Domain Account Creation | Event ID 4720 (creation of privileged accounts) |
| **Privilege Escalation**| T1098 | Account Manipulation | Event ID 4738 (modification of sensitive groups / ACLs) |

---

## 3. Incident Triage & Investigation Workflows

### Scenario A: Kerberoasting Triage
Kerberoasting involves attackers requesting Service Principal Name (SPN) service tickets (TGS) and offline cracking service account passwords.

1. **Detect Event Logs:**
   - Query Windows Security Log for **Event ID 4769** ("A Kerberos service ticket was requested").
   - Filter criteria:
     - `ServiceName` != computer accounts (`$`), `krbtgt`.
     - `TicketOptions` indicates weak encryption or RC4 (`0x40810000` / `0x17`).
     - Excessive requests originating from a single non-privileged user account within a short time window.
2. **KQL Threat Hunting Query (Microsoft Sentinel / Defender):**
   ```kql
   SecurityEvent
   | where EventID == 4769
   | where ServiceName !endswith "$" and ServiceName != "krbtgt"
   | where TicketEncryptionType == "0x17" // RC4
   | summarize RequestCount = count() by IpAddress, TargetUserName, AccountName
   | where RequestCount > 10
   | sort by RequestCount desc
   ```
3. **Containment & Remediation:**
   - Rotate the compromised service account password immediately with high entropy (minimum 128 bits / 25+ characters).
   - Migrate service accounts from RC4 to **AES-128 / AES-256** encryption (`msDS-SupportedEncryptionTypes`).
   - Implement Group Managed Service Accounts (**gMSA**) to eliminate manual password management.

---

### Scenario B: DCSync Triage
An attacker with `Replicating Directory Changes` or `Replicating Directory Changes All` rights queries the Domain Controller to dump password hashes.

1. **Detect Event Logs:**
   - Query Security Log for **Event ID 4662** ("An operation was performed on an object").
   - Access Mask: `0x100` (`CONTROL_ACCESS`).
   - Extended Rights GUID: 
     - `11316f70-8bcf-11d1-a3f0-00aa0031c784` (Replicating Directory Changes)
     - `11316f73-8bcf-11d1-a3f0-00aa0031c784` (Replicating Directory Changes All)
   - Verify that the source SID does **not** belong to a known legitimate Domain Controller.
2. **Containment & Remediation:**
   - Isolate the attacking machine / compromised endpoint immediately via network containment or EDR block.
   - Audit ACLs on the Domain object using `PowerView` or `dsacls` to strip unauthorized replication rights from standard accounts.
   - Force a global enterprise credential reset (`krbtgt` password reset **twice** to invalidate existing Golden Tickets).

---

## 4. Tier Administration Model
To prevent lateral movement and privilege escalation, organizations must enforce a strict Tiered Administration Model:

```
+-----------------------------------------------------------------+
| Tier 0: Enterprise Control (Domain Controllers, PKI, ADFS,      |
|         Active Directory Tier 0 Administrators)                 |
+-----------------------------------------------------------------+
                                  ▲
                                  │ (No upward trust / access)
                                  ▼
+-----------------------------------------------------------------+
| Tier 1: Enterprise Servers & Applications (Database Servers,    |
|         Virtualization Hosts, Management Platforms)             |
+-----------------------------------------------------------------+
                                  ▲
                                  │ (No upward trust / access)
                                  ▼
+-----------------------------------------------------------------+
| Tier 2: Enduser Workstations & Devices (Developer Laptops,      |
|         Standard Desktops, Conference Room PCs)                 |
+-----------------------------------------------------------------+
```

### Core Rules:
1. **No Cross-Tier Contamination:** Tier 2 credentials must never log into Tier 1 or Tier 0 assets. Tier 1 credentials must never log into Tier 2.
2. **Dedicated Administrative Workstations (PAWs):** Tier 0 administrators must use hardened, dedicated Privileged Access Workstations with strict outbound firewall rules and credential guard enabled.
3. **Authentication Silos & Authentication Policies:** Restrict sensitive accounts to specific host clusters using Windows Server Authentication Policies.

---

## 5. Forest Recovery & Domain Controller Restoration
In the event of a catastrophic forest compromise (e.g., persistent ransomware, full domain administrative takeover, or root cert compromise):

### Phase 1: Preparation & Isolation
1. Disconnect all WAN connections, site-to-site VPNs, and inter-forest trusts immediately.
2. Identify a clean, verified offline backup of Active Directory (System State backup / Bare Metal Recovery via Veeam, Azure Backup, or Windows Server Backup).

### Phase 2: Non-Authoritative vs Authoritative Restore
- **Non-Authoritative Restore:** Restores the NTDS.dit database to the point in time of the backup across all restored Domain Controllers, allowing normal replication to synchronize subsequent changes.
- **Authoritative Restore (Selective):** Used to recover specific deleted or altered objects (such as organizational units or accounts) by marking them as authoritative (`ntdsutil -> authoritative restore`).

### Phase 3: Step-by-Step Restoration Protocol
1. **Rebuild Primary Domain Controller (PDC Emulator):**
   - Perform a Bare Metal Restore (BMR) or Non-Authoritative System State restore on the designated primary DC in an isolated network segment (Isolated Lab / Air-Gapped VLAN).
2. **Reset Critical Credentials:**
   - Immediately execute a **double reset** of the `krbtgt` account password to invalidate all Kerberos Ticket Granting Tickets across the entire forest.
   - Reset built-in Administrator passwords and enterprise service account keys.
3. **Clean Up Lingering Objects:**
   - Run `repadmin /removelingeringobjects` across all domain controllers to purge malicious objects injected during the breach window.
4. **Re-establish Trusts & Verify Integrity:**
   - Run `dcdiag /v` and `repadmin /replsum` to verify replication health, DNS SRV record registration, and SYSVOL synchronization before reconnecting external network circuits.
