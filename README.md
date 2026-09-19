# Active Directory Security Auditing & Hardening Lab

Simulated adversary techniques including Kerberoasting, AS-REP roasting, and BloodHound attack path analysis within a multi-forest AD environment. Hardened domain policies against ticket extraction and eliminated legacy weak ciphers.

## Overview

This repository documents hands-on Active Directory (AD) security hardening, attack simulation, and telemetry detection engineering. It demonstrates how enterprise environments are compromised via identity vectors and how SOC analysts detect and mitigate these paths.

## Key Components

- **Attack Path Analysis (`BloodHound`)**: Mapped Domain Controller attack paths, identifying high-value targets, unconstrained delegation, and Kerberoastable service accounts.
- **Credential Harvesting Simulation**: Executed Kerberoasting (`EventID 4769`) and AS-REP roasting to extract service ticket hashes.
- **Hardening & Remediation**: Implemented AES encryption enforcement (disabling RC4), fine-grained password policies (FGPP), and GPO hardening against ticket extraction (LSASS protection).
- **SIEM Detection Engineering**: Authored KQL queries to detect anomalous TGS request volumes and suspicious RC4 ticket requests.

## Directory Structure

- `audit-checklist.md` – Enterprise AD hardening checklist.
- `detection-rules.kql` – KQL detection rules for Kerberoasting and AS-REP roasting.
- `simulate-kerberoasting.ps1` – PowerShell script for simulated Kerberoasting discovery and telemetry testing.

## License

MIT