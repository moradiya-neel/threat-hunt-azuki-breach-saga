# Threat Hunt: THE AZUKI BREACH SAGA

<img width="1536" height="1024" alt="azuki" src="https://github.com/user-attachments/assets/8c388bc9-ec7b-42d1-9f0c-40cce89c3d3d" />

## Executive Summary

This document summarizes the complete threat hunting investigation conducted on Azuki Import/Export Trading Co. (梓貿易株式会社) following a devastating ransomware attack by the JADE SPIDER threat actor group, operating under their "SilentLynx" ransomware-as-a-service (RaaS) brand.

The investigation spanned **8 days of attacker dwell time** (November 19-27, 2025) and was conducted across **4 investigative parts**, analyzing over **90 flags** of malicious activity. The attack culminated in the encryption of **847,293 files** (847.2 GB) and exfiltration of **126.6 GB** of sensitive corporate data, with a ransom demand of **$850,000 USD** in Monero cryptocurrency.

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Threat Actor | JADE SPIDER |
| Ransomware Brand | SilentLynx |
| Affiliate ID | SL-AFF-2847 |
| Operation Type | Ransomware-as-a-Service (RaaS) |
| Attack Model | Double Extortion (Encryption + Data Leak) |
| Encryption | AES-256-GCM with X25519 ECDH key exchange |
| File Extension | .lynx |

---

## Investigation Overview

### Part 1 Port of Entry: Initial Compromise (November 19, 2025)

**Target System:** azuki-sl (10.1.0.204) - Employee Workstation

**Summary:** The attack began with a phishing email containing a malicious attachment. The threat actor established initial access on an employee workstation, deployed credential harvesting tools, created a backdoor account for persistence, and exfiltrated stolen credentials via Discord webhooks.

| Metric | Value |
|--------|-------|
| Flags Investigated | 20 |
| Duration | ~35 minutes |
| Initial Access | Phishing email |
| Credentials Stolen | Multiple domain accounts |
| Persistence | Backdoor account "support" |
| Exfiltration | Discord webhooks |

**Key Findings:**
- Phishing payload executed by user kenji.sato
- Credential dumping tool (mm.exe) deployed
- Backdoor account "support" created for persistence
- Stolen credentials exfiltrated via Discord C2 channel
- Staging directory: `C:\ProgramData\WindowsCache`

---

### Part 2 Cargo Hold: File Server Compromise (November 22, 2025)

**Target System:** azuki-fileserver01 (10.1.0.188) - Corporate File Server

**Summary:** Three days after initial access, the attacker pivoted to the corporate file server using RDP with stolen credentials. They performed extensive reconnaissance, deployed additional credential harvesting tools, and exfiltrated sensitive corporate data, including financial records, contracts, and employee information.

| Metric | Value |
|--------|-------|
| Flags Investigated | 20 |
| Duration | ~2 hours |
| Lateral Movement | RDP (T1021.001) |
| Compromised Account | fileadmin |
| Data Exfiltrated | Financial, contracts, HR data |
| Exfiltration Method | file.io |

**Key Findings:**
- RDP lateral movement from azuki-sl
- Credential dumping tool (pd.exe) deployed
- Extensive file server reconnaissance
- Sensitive data staged and compressed
- Exfiltration via file.io cloud service
- Staging directory: `C:\Windows\Logs\CBS`

---

### Part 3 Bridge Takeover: CEO Workstation Compromise (November 25, 2025)

**Target System:** azuki-adminpc (10.1.0.108) - CEO Administrative PC

**Summary:** The attacker escalated their access by compromising the CEO's administrative workstation. This yielded high-value credentials, including the KeePass password database with its master password. The attacker deployed Meterpreter for C2, extracted the custom SilentLynx implant, and exfiltrated the most sensitive corporate data.

| Metric | Value |
|--------|-------|
| Flags Investigated | 25 |
| Duration | ~2 hours |
| Lateral Movement | RDP (T1021.001) |
| Compromised Account | yuki.tanaka (CEO) |
| High-Value Credentials | KeePass database + master password |
| Exfiltration Method | gofile.io |

**Key Findings:**
- RDP lateral movement from azuki-sl
- Mimikatz (m.exe) deployed for credential extraction
- KeePass database (Azuki-Passwords.kdbx) exfiltrated with master password
- Chrome saved passwords extracted
- Meterpreter C2 beacon established
- SilentLynx implant (silentlynx.exe) extracted and staged
- Backdoor account "yuki.tanaka2" created
- Exfiltration to gofile.io (45.112.123.227)
- Staging directory: `C:\Windows\Temp\cache\`

---

### Part 4 Dead in the Water: Ransomware Deployment (November 25-27, 2025)

**Target Systems:** All systems including azuki-backupsrv (10.1.0.189) - Backup Server

**Summary:** In the final phase, the attacker pivoted to the Linux backup server via SSH, systematically destroyed all backup data, disabled recovery mechanisms across all Windows systems, deployed the SilentLynx ransomware via PsExec, and completed encryption of the entire environment.

| Metric | Value |
|--------|-------|
| Flags Investigated | 26 |
| Active Duration | ~39 minutes |
| Lateral Movement | SSH (T1021.004), PsExec (T1021.002) |
| Compromised Account | backup-admin |
| Backups Destroyed | 14 directories (ALL backups) |
| Files Encrypted | 847,293 |
| Data Encrypted | 847.2 GB |
| Ransom Demand | $850,000 USD |

**Key Findings:**
- SSH lateral movement to the Linux backup server
- Plaintext credentials discovered (`all-credentials.txt`)
- Destruction toolkit (destroy.7z) downloaded from litter.catbox.moe
- ALL backup directories recursively deleted (`rm -rf /backups/*`)
- Cron service stopped and disabled
- PsExec deployment of silentlynx.exe to all Windows systems
- Comprehensive recovery inhibition:
  - Shadow copies deleted (vssadmin, wmic)
  - Shadow storage limited to 401MB
  - Backup catalog deleted (wbadmin)
  - Windows Recovery disabled (bcdedit)
  - Security services stopped (Defender, VSS, wbengine)
  - File-locking processes killed (SQL, Office apps)
- Persistence via Registry Run keys and Scheduled Tasks
- USN Journal deleted for anti-forensics
- Ransom notes (SILENTLYNX_README.txt) deployed
- Encryption completed November 27, 2025, at 05:48:14 UTC

---

## Complete Attack Path

```
                                    JADE SPIDER Attack Flow
                                    ========================

    [INTERNET]                                                      [TOR NETWORK]
        │                                                                 │
        │ Phishing Email                                                  │
        ▼                                                                 │
┌─────────────────┐     RDP      ┌─────────────────┐     RDP      ┌─────────────────┐
│    azuki-sl     │─────────────▶│azuki-fileserver │              │  azuki-adminpc  │
│   10.1.0.204    │              │    10.1.0.188   │              │    10.1.0.108   │
│   (Beachhead)   │──────────────────────────────────────────────▶│    (CEO PC)     │
│                 │                     │                         │                 │
│  • Nov 19       │                     │                         │  • Nov 25       │
│  • mm.exe       │                     │                         │  • Mimikatz     │
│  • Discord C2   │                     │                         │  • KeePass      │
│  • "support"    │                     │                         │  • Meterpreter  │
└─────────────────┘                     │                         └────────┬────────┘
        ▲                               │                                  │
        │                               │                                  │ SSH
        │                               ▼                                  ▼
        │                      ┌─────────────────┐                ┌─────────────────┐
        │        PsExec        │  azuki-logistics│                │ azuki-backupsrv │
        │◀─────────────────────│    10.1.0.102   │                │    10.1.0.189   │
        │                      │                 │                │  (Linux Backup) │
        │                      │  • Nov 25       │                │                 │
        │                      │  • silentlynx   │                │  • Nov 25       │
        │                      └─────────────────┘                │  • rm -rf       │
        │                               ▲                         │  • ALL BACKUPS  │
        │                               │                         │    DESTROYED    │
        │            PsExec             │         PsExec          └─────────────────┘
        └───────────────────────────────┴─────────────────────────────────┘
                                        │
                                        │
                              ┌─────────▼─────────┐
                              │   SILENTLYNX.EXE  │
                              │   DEPLOYED TO ALL │
                              │      SYSTEMS      │
                              │                   │
                              │  847,293 FILES    │
                              │  ENCRYPTED        │
                              │                   │
                              │  $850,000 RANSOM  │
                              └───────────────────┘
```

---

## Complete Timeline

| Date | Time | Part | System | Key Activity |
|------|------|------|--------|--------------|
| Nov 19 | Morning | Part 1 | azuki-sl | Phishing email delivered and executed |
| Nov 19 | ~35 min | Part 1 | azuki-sl | Credential theft, persistence, exfiltration |
| Nov 22 | ~2 hours | Part 2 | azuki-fileserver01 | File server compromise, data exfiltration |
| Nov 25 | 4:06 AM | Part 3 | azuki-adminpc | RDP to CEO workstation |
| Nov 25 | 4:06-6:00 AM | Part 3 | azuki-adminpc | Credential theft, KeePass, Meterpreter |
| Nov 25 | 5:31 AM | Part 4 | azuki-adminpc | Defender processes killed |
| Nov 25 | 5:39 AM | Part 4 | azuki-backupsrv | SSH to backup server |
| Nov 25 | 5:47 AM | Part 4 | azuki-backupsrv | ALL backups destroyed |
| Nov 25 | 5:58 AM | Part 4 | azuki-adminpc | Recovery inhibition begins |
| Nov 25 | 6:03-6:05 AM | Part 4 | All Windows | PsExec ransomware deployment |
| Nov 25 | 6:05-6:07 AM | Part 4 | All Windows | Ransom notes dropped |
| Nov 25 | 6:10 AM | Part 4 | azuki-adminpc | USN Journal deleted |
| Nov 27 | 5:48 AM | Part 4 | All systems | Encryption completed |

**Total Dwell Time:** 8 days (November 19-27, 2025)

---

## Systems Compromised

| System | IP Address | Role | OS | Part | Status |
|--------|------------|------|-----|------|--------|
| azuki-sl | 10.1.0.204 | Workstation | Windows 11 | Part 1 | Encrypted |
| azuki-fileserver01 | 10.1.0.188 | File Server | Server 2022 | Part 2 | Encrypted |
| azuki-adminpc | 10.1.0.108 | CEO Admin PC | Windows 11 | Part 3 | Encrypted |
| azuki-backupsrv | 10.1.0.189 | Backup Server | Ubuntu 22.04 | Part 4 | Backups Destroyed |
| azuki-logistics | 10.1.0.102 | Logistics PC | Windows | Part 4 | Encrypted |

**Total Systems Compromised:** 5

---

## Accounts Compromised

| Account | System | Part | Purpose |
|---------|--------|------|---------|
| kenji.sato | azuki-sl | Part 1 | Initial access |
| support | azuki-sl | Part 1 | Backdoor account |
| fileadmin | azuki-fileserver01 | Part 2 | File server access |
| yuki.tanaka | azuki-adminpc | Part 3 | CEO account |
| yuki.tanaka2 | azuki-adminpc | Part 3 | Backdoor account |
| backup-admin | azuki-backupsrv | Part 4 | Backup server access |

**Total Accounts Compromised:** 6 (including 2 backdoor accounts created)

---

## Data Impact Summary

### Data Exfiltrated (126.6 GB Total)

| Category | Size | Part |
|----------|------|------|
| Financial Records & Tax Documents | 34.2 GB | Part 2/3 |
| Client Contracts & PII | 28.7 GB | Part 2/3 |
| Internal Communications | 32.1 GB | Part 2/3 |
| Proprietary Business Data | 18.3 GB | Part 2/3 |
| Employee HR Records | 12.4 GB | Part 2/3 |
| Banking & Payment Credentials | 890 MB | Part 3 |

### Data Encrypted

| Metric | Value |
|--------|-------|
| Files Encrypted | 847,293 |
| Data Encrypted | 847.2 GB |
| File Extension | .lynx |

### Backups Destroyed

| Directory | Contents |
|-----------|----------|
| /backups/archives | Archived backups |
| /backups/azuki-adminpc | CEO PC backups |
| /backups/azuki-fileserver | File server backups |
| /backups/azuki-logisticspc | Logistics PC backups |
| /backups/config-backups | Configuration backups |
| /backups/configs | System configurations |
| /backups/daily | Daily backup rotation |
| /backups/database-backups | Database dumps |
| /backups/databases | Database files |
| /backups/fileserver | File server data |
| /backups/logs | Log archives |
| /backups/monthly | Monthly backup rotation |
| /backups/weekly | Weekly backup rotation |
| /backups/workstations | Workstation backups |

---

## Malware & Tools Used

| Tool | Filename | Part | Purpose |
|------|----------|------|---------|
| Credential Dumper | mm.exe | Part 1 | Password extraction |
| Credential Dumper | pd.exe | Part 2 | Password extraction |
| Mimikatz | m.exe | Part 3 | Credential theft |
| Meterpreter | meterpreter.exe | Part 3 | C2 beacon |
| SilentLynx Implant | silentlynx.exe | Part 3/4 | Custom implant/ransomware |
| Destruction Kit | destroy.7z | Part 4 | Backup destruction tools |
| PsExec | PsExec64.exe | Part 4 | Remote execution |
| 7-Zip | 7za.exe | Part 2/3 | Data compression |

---

## Exfiltration Infrastructure

| Part | Service | Destination |
|------|---------|-------------|
| Part 1 | Discord | Discord webhooks (C2) |
| Part 2 | file.io | file.io cloud storage |
| Part 3 | gofile.io | store1.gofile.io (45.112.123.227) |
| Part 4 | litter.catbox.moe | Malware download (destroy.7z) |

---

## MITRE ATT&CK Coverage

### Tactics Observed

| Tactic | Techniques | Parts |
|--------|------------|-------|
| Initial Access | T1566 (Phishing) | Part 1 |
| Execution | T1204.002 (Malicious File) | All Parts |
| Persistence | T1136 (Create Account), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task) | Parts 1, 3, 4 |
| Privilege Escalation | T1078 (Valid Accounts) | All Parts |
| Defense Evasion | T1562.001 (Disable Tools), T1070.004 (File Deletion) | Parts 3, 4 |
| Credential Access | T1003 (Credential Dumping), T1555 (Credentials from Password Stores), T1552.001 (Credentials In Files) | All Parts |
| Discovery | T1083 (File Discovery), T1087 (Account Discovery), T1082 (System Discovery) | All Parts |
| Lateral Movement | T1021.001 (RDP), T1021.004 (SSH), T1021.002 (SMB/Admin Shares) | Parts 2, 3, 4 |
| Collection | T1560.001 (Archive Data) | Parts 2, 3 |
| Command and Control | T1105 (Ingress Tool Transfer), T1071 (Application Layer Protocol) | All Parts |
| Exfiltration | T1567 (Exfiltration Over Web Service) | Parts 1, 2, 3 |
| Impact | T1485 (Data Destruction), T1486 (Data Encrypted), T1489 (Service Stop), T1490 (Inhibit Recovery) | Part 4 |

### Complete Technique List

| ID | Technique | Parts |
|----|-----------|-------|
| T1566 | Phishing | Part 1 |
| T1204.002 | User Execution: Malicious File | All |
| T1136.001 | Create Account: Local Account | Parts 1, 3 |
| T1547.001 | Registry Run Keys / Startup Folder | Parts 3, 4 |
| T1053.005 | Scheduled Task | Part 4 |
| T1078.002 | Valid Accounts: Domain Accounts | All |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Parts 3, 4 |
| T1070.004 | Indicator Removal: File Deletion | Part 4 |
| T1003.001 | OS Credential Dumping: LSASS Memory | Parts 1, 2, 3 |
| T1555.003 | Credentials from Web Browsers | Part 3 |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Part 3 |
| T1552.001 | Unsecured Credentials: Credentials In Files | Parts 3, 4 |
| T1083 | File and Directory Discovery | All |
| T1087.001 | Account Discovery: Local Account | Parts 1, 4 |
| T1082 | System Information Discovery | All |
| T1021.001 | Remote Services: RDP | Parts 2, 3 |
| T1021.004 | Remote Services: SSH | Part 4 |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Part 4 |
| T1570 | Lateral Tool Transfer | Part 4 |
| T1560.001 | Archive Collected Data: Archive via Utility | Parts 2, 3 |
| T1105 | Ingress Tool Transfer | All |
| T1071.001 | Application Layer Protocol: Web Protocols | All |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Parts 1, 2, 3 |
| T1485 | Data Destruction | Part 4 |
| T1486 | Data Encrypted for Impact | Part 4 |
| T1489 | Service Stop | Part 4 |
| T1490 | Inhibit System Recovery | Part 4 |

---

## Vulnerabilities Exploited

The ransom note included a vulnerability assessment identifying the following security gaps:

| ID | Severity | Finding | Exploited In |
|----|----------|---------|--------------|
| SL-V001 | CRITICAL | Weak email security - Phishing payload executed | Part 1 |
| SL-V002 | CRITICAL | Insufficient network segmentation | Parts 2, 3, 4 |
| SL-V003 | CRITICAL | Credential reuse across systems | All Parts |
| SL-V004 | CRITICAL | Inadequate backup isolation (no air-gap) | Part 4 |
| SL-V005 | CRITICAL | Missing EDR on Linux infrastructure | Part 4 |
| SL-V006 | HIGH | Local administrator password reuse | Parts 2, 3 |
| SL-V007 | HIGH | Lack of MFA on administrative accounts | All Parts |

---

## Recovery Assessment

### Available Recovery Options

| Recovery Method | Status | Reason |
|-----------------|--------|--------|
| Linux Backups | Destroyed | `rm -rf /backups/` |
| Shadow Copies | Deleted | `vssadmin delete shadows /all` |
| Windows Backup Catalog | Deleted | `wbadmin delete catalog` |
| System Recovery | Disabled | `bcdedit recoveryenabled No` |
| Shadow Storage | Limited | Reduced to 401MB |
| Forensic Evidence | Limited | USN Journal deleted |

### Why Paying the Ransom is Not Recommended

1. **No Guarantee of Decryption** - Attackers may not provide working decryption keys, or the decryption tools may be buggy and corrupt files further

2. **Funds Criminal Operations** - Payment directly finances future attacks, enables development of more sophisticated tools, and supports the RaaS ecosystem

3. **Marks You as a Target** - Paying shows willingness to pay, attackers may return, and your organization may be shared among criminal groups as a "payer"

4. **No Guarantee Data Won't Be Leaked** - Double extortion is standard practice; even after payment, attackers may still publish the 126.6 GB of stolen data

5. **Legal and Regulatory Issues** - Some jurisdictions restrict ransom payments, paying sanctioned entities can result in penalties, and may violate cyber insurance policy terms

6. **Doesn't Address Root Cause** - Payment doesn't fix exploited vulnerabilities, attackers may have left backdoors (persistence mechanisms found), and without remediation, you remain vulnerable

---

## Recommendations

### Immediate Actions

1. **Isolate all compromised systems** from the network
2. **Preserve available evidence** despite anti-forensic measures
3. **Assess offline/cloud backups** not connected to the network
4. **Engage professional incident response** team
5. **Report to law enforcement** (FBI IC3, local authorities)
6. **Notify affected parties** per regulatory requirements
7. **Check for decryptors** (No More Ransom project)

### Short-term Remediation

1. **Reset ALL credentials** - Assume all passwords compromised
2. **Remove persistence mechanisms**:
   - Delete backdoor accounts (support, yuki.tanaka2)
   - Remove registry Run keys (SystemHealthMonitor, WindowsSecurityHealth)
   - Delete scheduled tasks (SecurityHealthService)
3. **Rebuild compromised systems** from known-good images
4. **Block IOCs** at network perimeter
5. **Implement emergency MFA** on all accounts

### Long-term Security Improvements

| Priority | Recommendation | Addresses |
|----------|----------------|-----------|
| Critical | Implement air-gapped backup infrastructure | SL-V004 |
| Critical | Deploy EDR on ALL systems, including Linux | SL-V005 |
| Critical | Implement network segmentation | SL-V002 |
| Critical | Enforce MFA on all accounts | SL-V007 |
| High | Email security enhancement (SPF, DKIM, DMARC, sandbox) | SL-V001 |
| High | Privileged Access Management (PAM) solution | SL-V006 |
| High | Credential hygiene - unique passwords per system | SL-V003 |
| High | Regular backup testing and recovery drills | SL-V004 |
| Medium | Security awareness training (phishing) | SL-V001 |
| Medium | Implement SIEM with 24/7 monitoring | Detection |
| Medium | Regular penetration testing | Validation |
| Medium | Incident response plan development | Preparedness |

---

## Investigation Deliverables

### Part 1: Port of Entry
- [Part 1 README](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-1-port-of-entry/README.md)
- [Part 1 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/indicators-of-compromise.md)
- [Part 1 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/chronological-timeline.md)

### Part 2: Cargo Hold
- [Part 2 README](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-2-cargo-hold/README.md)
- [Part 2 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/indicators-of-compromise.md)
- [Part 2 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/chronological-timeline.md)

### Part 3: Bridge Takeover
- [Part 3 README](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-3-bridge-takeover/README.md)
- [Part 3 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/indicators-of-compromise.md)
- [Part 3 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/chronological-timeline.md)

### Part 4: Dead in the Water
- [Part 4 README](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-4-dead-in-the-water/README.md)
- [Part 4 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/indicators-of-compromise.md)
- [Part 4 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/chronological-timeline.md)

---

## Investigation Statistics

| Metric | Value |
|--------|-------|
| Total Flags Investigated | 91 |
| Investigation Parts | 4 |
| Total Dwell Time | 8 days |
| Systems Compromised | 5 |
| Accounts Compromised | 6 |
| Data Exfiltrated | 126.6 GB |
| Files Encrypted | 847,293 |
| Data Encrypted | 847.2 GB |
| Backups Destroyed | 14 directories |
| Ransom Demand | $850,000 USD |
| MITRE Techniques Identified | 27 |

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Ransom Note](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/ransom-note.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [FBI IC3 Reporting](https://www.ic3.gov/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)

---

## Document Information

| Field | Value |
|-------|-------|
| Classification | CONFIDENTIAL |
| Created | January 2026 |
| Author | Neel Moradiya |
| Version | 1.0 |
| Status | Complete |

