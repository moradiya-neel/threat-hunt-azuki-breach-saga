# THE AZUKI BREACH SAGA - Part 4: Dead in the Water

<img width="740" height="1100" alt="Screenshot 2026-01-22 at 3 50 54 PM" src="https://github.com/user-attachments/assets/1f711423-5b81-4bf5-80d0-1dfba95c12d4" />

## Executive Summary

This report documents the findings from Part 4 of the threat hunting investigation conducted on Azuki Import/Export Trading Co. This phase covers the final stage of the JADE SPIDER intrusion - the destruction of backup infrastructure and deployment of SilentLynx ransomware across the enterprise.

On November 25, 2025, the threat actors pivoted from the compromised CEO admin PC to the Linux backup server, systematically destroyed all backup data, disabled recovery mechanisms across Windows systems, and deployed the SilentLynx ransomware. The encryption was completed on November 27, 2025, at 05:48:14 UTC, with ransom notes demanding $850,000 USD in Monero.

The investigation revealed a sophisticated, multi-phase attack that eliminated all recovery options before encrypting 847,293 files across the enterprise.

---

## Scenario Overview

### Incident Brief

| Field | Detail |
|-------|--------|
| Company | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| Situation | Ransom notes discovered across all systems. Threat actors destroyed backup infrastructure and deployed ransomware. |
| CEO Questions | How did they reach backups? What did they destroy? How did ransomware spread? Can we recover? |
| Evidence Available | Microsoft Defender for Endpoint logs (via Azure Log Analytics) |

### Investigation Scope

| Parameter | Value |
|-----------|-------|
| Time Period | November 25 - November 27, 2025 |
| Backup Server Pivot | November 25, 2025, 5:39 AM |
| Encryption Timestamp | November 27, 2025, 5:48:14 AM |
| Data Source | Microsoft Defender for Endpoint logs (Azure Log Analytics) |

### Systems in Scope

| Device | IP Address | Role | OS |
|--------|------------|------|-----|
| azuki-sl | 10.1.0.204 | Workstation (Beachhead) | Windows 11 |
| azuki-adminpc | 10.1.0.108 | Admin PC (CEO) | Windows 11 |
| azuki-fileserver01 | 10.1.0.188 | File Server | Server 2022 |
| azuki-backupsrv | 10.1.0.189 | Backup Server | Ubuntu 22.04 |

### Supporting Documents

- [Attack Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/chronological-timeline.md) - Chronological breakdown of attacker activity
- [Indicators of Compromise](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/indicators-of-compromise.md) - Complete IOC list with detection signatures

### Connection to Previous Parts

| Part | Date | Target | Key Activity |
|------|------|--------|--------------|
| Part 1 | November 19, 2025 | azuki-sl | Initial access, credential theft, persistence |
| Part 2 | November 22, 2025 | azuki-fileserver01 | File server compromise, data exfiltration |
| Part 3 | November 25, 2025 | azuki-adminpc | CEO PC compromise, extensive credential theft |
| Part 4 | November 25-27, 2025 | azuki-backupsrv + All systems | Backup destruction, ransomware deployment |

---

## Ransom Note Analysis - ([Ransom Note](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/ransom-note.md))

A ransom note was discovered on all encrypted systems from the "SilentLynx Security Team" - confirming the threat actor attribution to JADE SPIDER (SilentLynx is a known alias).

### Key Details from Ransom Note

| Field | Value |
|-------|-------|
| Threat Actor | SilentLynx Security Team |
| Affiliate ID | SL-AFF-2847 |
| Victim Key | AZUKI-BC844-1127 |
| Encryption Algorithm | AES-256-GCM |
| Key Exchange | X25519 ECDH |
| File Extension | .lynx |
| Files Encrypted | 847,293 |
| Data Encrypted | 847.2 GB |
| Data Exfiltrated | 126.6 GB |
| Ransom Demand | $850,000 USD in Monero |
| Payment Deadline | 72 hours |

### Vulnerabilities Exploited (per Ransom Note)

| ID | Severity | Finding |
|----|----------|---------|
| SL-V001 | CRITICAL | Weak email security - Phishing payload executed |
| SL-V002 | CRITICAL | Insufficient network segmentation |
| SL-V003 | CRITICAL | Credential reuse across systems |
| SL-V004 | CRITICAL | Inadequate backup isolation (no air-gap) |
| SL-V005 | CRITICAL | Missing EDR on Linux infrastructure |
| SL-V006 | HIGH | Local administrator password reuse |
| SL-V007 | HIGH | Lack of MFA on administrative accounts |

---

## Findings

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH from azuki-adminpc to azuki-backupsrv |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec deployment |
| Credential Access | Valid Accounts: Domain Accounts | T1078.002 | backup-admin, kenji.sato, fileadmin |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | all-credentials.txt |
| Discovery | File and Directory Discovery | T1083 | ls, find commands on backup server |
| Discovery | Account Discovery: Local Account | T1087.001 | cat /etc/passwd |
| Command and Control | Ingress Tool Transfer | T1105 | curl download of destroy.7z |
| Impact | Data Destruction | T1485 | rm -rf /backups/ |
| Impact | Service Stop | T1489 | systemctl stop/disable cron, net stop services |
| Impact | Inhibit System Recovery | T1490 | vssadmin, bcdedit, wbadmin commands |
| Impact | Data Encrypted for Impact | T1486 | SilentLynx ransomware encryption |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Stopped Defender, killed security processes |
| Defense Evasion | Indicator Removal on Host: File Deletion | T1070.004 | fsutil usn deletejournal |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | WindowsSecurityHealth registry key |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | SecurityHealthService scheduled task |
| Execution | User Execution: Malicious File | T1204.002 | silentlynx.exe deployment |
| Lateral Movement | Lateral Tool Transfer | T1570 | PsExec copy of silentlynx.exe |

---

## CEO Questions Answered

### 1. How did they get to our backup infrastructure?

The attacker used SSH from the compromised CEO admin PC (azuki-adminpc) to access the Linux backup server (azuki-backupsrv) using the `backup-admin` account. The credentials were likely obtained from:
- The KeePass database exfiltrated in Part 3
- The `all-credentials.txt` file was discovered on the backup server itself

**Command:** `"ssh.exe" backup-admin@10.1.0.189`

### 2. What exactly did they destroy?

The attacker executed `rm -rf` to delete ALL backup directories:
- /backups/archives
- /backups/azuki-adminpc
- /backups/azuki-fileserver
- /backups/azuki-logisticspc
- /backups/config-backups
- /backups/configs
- /backups/daily
- /backups/database-backups
- /backups/databases
- /backups/fileserver
- /backups/logs
- /backups/monthly
- /backups/weekly
- /backups/workstations

They also stopped and disabled the cron service to prevent any scheduled backup jobs from running.

### 3. How did the ransomware spread so fast?

The attacker used **PsExec64.exe** to remotely deploy `silentlynx.exe` to all Windows systems simultaneously:
- Used credentials stolen throughout the intrusion (kenji.sato, fileadmin)
- Copied and executed the ransomware on each target
- Completed deployment to 3 systems in under 2 minutes

### 4. Can we recover?

**Unfortunately, recovery options are extremely limited:**

| Recovery Method | Status | Reason |
|-----------------|--------|--------|
| Linux Backups | Destroyed | rm -rf /backups/ |
| Shadow Copies | Deleted | vssadmin delete shadows /all |
| Windows Backup | Disabled | wbadmin delete catalog |
| System Recovery | Disabled | bcdedit recoveryenabled No |
| Forensic Evidence | Limited | USN journal deleted |

**Possible Recovery Options:**
1. Offline/air-gapped backups (if they exist)
2. Cloud backups not connected to the network
3. Third-party backup services
4. Pay the ransom (not recommended)

---

## Recommendations

### Immediate Actions

1. **Isolate all systems** - Prevent further spread
2. **Preserve evidence** - Despite journal deletion, some artifacts may remain
3. **Assess offline backups** - Check for any air-gapped or cloud backups
4. **Engage incident response** - Professional forensic analysis
5. **Report to authorities** - FBI IC3, local law enforcement

### Long-term Improvements

1. **Air-gapped backups** - Implement offline backup storage
2. **Network segmentation** - Isolate backup infrastructure
3. **MFA everywhere** - Especially for administrative accounts
4. **EDR on all systems** - Including Linux servers
5. **Credential management** - No plaintext credential storage
6. **Privileged Access Management** - Limit and monitor admin access
7. **Backup testing** - Regular recovery drills

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Ransome Note](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/ransom-note.md)
- [Additional Details - By Threat Hunt Organizor](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/additional-details.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Summary - The AZUKI BREACH SAGA](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/README.md)
- [Part 1 Investigation Report](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-1-port-of-entry)
- [Part 2 Cargo Hold](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-2-cargo-hold)
- [Part 3 Bridge Takeover](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-3-bridge-takeover)

