# BloodHound Attack Path Analysis Walkthrough

## 🧭 Overview

**BloodHound** is a single-page JavaScript application compiled with Electron, powered by a Neo4j database, that uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. 

In this lab, BloodHound is used by the red team to identify privileged attack paths and by the blue team to audit misconfigurations and prioritize remediation.

---

## 🛠️ Lab Setup & Collection

### 1. Prerequisites
- **Attacker Machine:** Kali Linux (`10.0.0.99`)
- **Collector:** SharpHound (`SharpHound.exe` or PowerShell script)
- **Database / UI:** Neo4j Community Edition + BloodHound GUI

### 2. Running SharpHound Collection
From a domain-joined Windows workstation (`WS01`) or via WinRM from Kali, execute SharpHound to gather AD objects, sessions, ACLs, and trusts:

```powershell
# Run SharpHound with all collection methods
.\SharpHound.exe -CollectionMethod All -ZipFileName "AD_Audit_Collection.zip"
```

*Collection Methods included in `All`:*
- `Group` (Domain groups and memberships)
- `LocalAdmin` (Local Administrators group members on domain computers)
- `Session` (Active logged-on user sessions)
- `Trusts` (Domain trust relationships)
- `ACL` (Access Control Lists on AD objects)
- `Container` (OU and container permissions)

### 3. Ingesting Data into BloodHound
1. Start Neo4j:
   ```bash
   neo4j console
   ```
2. Launch BloodHound:
   ```bash
   bloodhound --no-sandbox &
   ```
3. Log in with default credentials (`neo4j / neo4j` — update on first login).
4. Drag and drop the generated `AD_Audit_Collection.zip` file into the BloodHound UI window to ingest data.

---

## 🔍 Key BloodHound Cypher Queries & Attack Paths

### 1. Shortest Path to Domain Admin
Finds the shortest escalation chain from a compromised standard user to Domain Administrator privileges.

- **BloodHound Pre-built Query:** *Find Shortest Path to Domain Admins*
- **Cypher Query:**
  ```cypher
  MATCH (p:Person {name: "STANDARDUSER@CORP.LOCAL"})
  MATCH (d:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  MATCH path = shortestPath((p)-[r:MemberOf|AdminTo|HasSession|Control|AllowedToDelegate|GenericAll|WriteDacl*1..15]->(d))
  RETURN path
  ```
- **Analyst Note:** Look for `GenericAll`, `WriteDacl`, or `ForceChangePassword` edges on users, groups, or OUs.

### 2. Kerberoastable Users
Identifies user accounts with SPNs that can be targeted for offline password cracking (MITRE T1558.003).

- **BloodHound Pre-built Query:** *Find Kerberoastable Users*
- **Cypher Query:**
  ```cypher
  MATCH (u:User {hasspn: true})
  RETURN u.name, u.title, u.pwdlastset
  ```
- **Remediation:** Ensure service accounts use strong, 25+ character passwords or transition to Group Managed Service Accounts (gMSAs).

### 3. Unconstrained Delegation
Finds computers configured for unconstrained delegation (T1558 / T1134). If an admin authenticates to these machines, their TGT is cached in memory, allowing complete domain compromise.

- **BloodHound Pre-built Query:** *Find Computers with Unconstrained Delegation*
- **Cypher Query:**
  ```cypher
  MATCH (c:Computer {unconstraineddelegation: true})
  RETURN c.name, c.operatingsystem
  ```
- **Remediation:** Disable unconstrained delegation; migrate to constrained or resource-based constrained delegation (RBCD).

### 4. AS-REP Roastable Users
Identifies accounts with pre-authentication disabled (MITRE T1558.004).

- **Cypher Query:**
  ```cypher
  MATCH (u:User {dontreqpreauth: true})
  RETURN u.name, u.userprincipalname
  ```

---

## 📸 Screenshots & Evidence (Placeholder Sections)

### Figure 1: BloodHound Database Ingestion Dashboard
```
+-------------------------------------------------------------+
| [ BloodHound Ingest Status: AD_Audit_Collection.zip ]       |
| ─────────────────────────────────────────────────────────── |
| Nodes Ingested:                                             |
|   - Users: 1,245       - Computers: 352      - Groups: 84   |
|   - Domains: 1         - OUs: 42             - GPOs: 28     |
| Edges Ingested: 14,892                                      |
| Status: SUCCESS (0 errors)                                  |
+-------------------------------------------------------------+
```

### Figure 2: Shortest Path to Domain Admin Graph
```
[ Standard User ] ──( MemberOf )──> [ IT Support Group ]
       │
       └──( GenericAll )──> [ Service Account ] ──( AdminTo )──> [ DC01 ] ──> [ DOMAIN ADMIN ]
```

---

## 🛡️ Remediation & Tiered Administration

1. **Tiered Administration Model:** Separate Tier 0 (Domain Controllers, AD Admins), Tier 1 (Servers, Enterprise Apps), and Tier 2 (Workstations). Prevent Tier 2 credentials from having admin access on Tier 0/1.
2. **Protected Users Security Group:** Add sensitive accounts to the *Protected Users* group to disable NTLM, RC4, and unconstrained delegation.
3. **ACL Hygiene:** Audit and remove excessive `GenericAll`, `WriteDacl`, and `Owner` permissions granted to non-admin users.
