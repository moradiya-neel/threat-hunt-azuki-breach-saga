# JADE SPIDER Threat Hunt - Part 2: Attack Timeline

This document provides a chronological timeline of the JADE SPIDER intrusion during Part 2 of the investigation, focusing on the attacker's return on November 22, 2025, and their activities on the file server (azuki-fileserver01).

---

## Timeline Overview

**Attack Date:** November 22, 2025

**Total Active Time:** Approximately 2 hours (12:27 AM - 2:26 AM)

**Dwell Time Since Initial Access:** ~54 hours (from Nov 19, 6:36 PM to Nov 22, 12:27 AM)

**Systems Affected:** azuki-sl (beachhead), azuki-fileserver01 (file server)

---

## Detailed Timeline

### Phase 1: Return Access (12:27 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 12:27:53 AM | azuki-sl | Return Connection | Attacker connects from new IP 159.26.106.98 using kenji.sato credentials | T1133, T1078 |

---

### Phase 2: Lateral Movement (12:38 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 12:38:47 AM | azuki-sl | RDP Initiation | `mstsc.exe /V:10.1.0.188` executed via PowerShell | T1021.001 |
| 12:38:49 AM | azuki-fileserver01 | Lateral Movement Success | fileadmin account logon from azuki-sl | T1021.001, T1550 |

---

### Phase 3: Discovery on File Server (12:40 AM - 12:42 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 12:40:09 AM | azuki-fileserver01 | Identity Check | `whoami.exe` | T1033 |
| 12:40:33 AM | azuki-fileserver01 | User Enumeration | `net.exe user` | T1087.001 |
| 12:40:46 AM | azuki-fileserver01 | Admin Enumeration | `net.exe localgroup administrators` | T1069.001 |
| 12:40:54 AM | azuki-fileserver01 | Share Discovery | `net.exe share` | T1135 |
| 12:41:16 AM | azuki-fileserver01 | Admin Enumeration | `net.exe localgroup administrators` (repeat) | T1069.001 |
| 12:42:01 AM | azuki-fileserver01 | Remote Share Enum | `net.exe view \\10.1.0.188` | T1135 |
| 12:42:24 AM | azuki-fileserver01 | Privilege Enum | `whoami.exe /all` | T1033 |
| 12:42:46 AM | azuki-fileserver01 | Network Config | `ipconfig.exe /all` | T1016 |
| 12:42:50 AM | azuki-fileserver01 | ARP Discovery | `ARP.EXE -a` | T1016 |

---

### Phase 4: Staging Setup (12:55 AM - 1:02 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 12:55:43 AM | azuki-fileserver01 | Hide Directory | `attrib.exe +h +s C:\Windows\Logs\CBS` | T1564.001 |
| 12:56:47 AM | azuki-fileserver01 | Script Download | `certutil.exe` downloads ex.ps1 (port 7331) | T1105, T1218 |
| 12:58:24 AM | azuki-fileserver01 | Script Download | `certutil.exe` retry (port 7331) | T1105, T1218 |
| 1:02:59 AM | azuki-fileserver01 | Script Download | `certutil.exe` fallback (port 8080) | T1105, T1218 |

---

### Phase 5: Data Collection (1:07 AM - 1:41 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 1:07:53 AM | azuki-fileserver01 | Data Staging | `xcopy.exe` copies IT-Admin share including IT-Admin-Passwords.csv | T1039, T1119, T1552.001 |
| 1:27:31 AM | azuki-fileserver01 | Version Check | `tar.exe --version` | - |
| 1:28:55 AM | azuki-fileserver01 | Archive Financial | `tar.exe -czf financial.tar.gz` | T1560.001 |
| 1:30:10 AM | azuki-fileserver01 | Archive Credentials | `tar.exe -czf credentials.tar.gz` | T1560.001 |
| 1:41:33 AM | azuki-fileserver01 | Archive Shipping | `tar.exe -czf shipping.tar.gz` | T1560.001 |

---

### Phase 6: Data Exfiltration (1:59 AM - 2:00 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 1:59:54 AM | azuki-fileserver01 | Exfil Credentials | `curl.exe` uploads credentials.tar.gz to file.io | T1567.002 |
| 2:00:01 AM | azuki-fileserver01 | Exfil Financial | `curl.exe` uploads financial.tar.gz to file.io | T1567.002 |
| 2:00:08 AM | azuki-fileserver01 | Exfil Contracts | `curl.exe` uploads contracts.zip to file.io | T1567.002 |
| 2:00:20 AM | azuki-fileserver01 | Exfil Shipping | `curl.exe` uploads shipping.tar.gz to file.io | T1567.002 |

---

### Phase 7: Credential Access (2:03 AM - 2:24 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 2:03:19 AM | azuki-fileserver01 | Tool Deployment | pd.exe (ProcDump) created in staging directory | T1036.003 |
| 2:24:44 AM | azuki-fileserver01 | LSASS Dump | `pd.exe -accepteula -ma 876 lsass.dmp` | T1003.001 |

---

### Phase 8: Persistence (2:10 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 2:10:50 AM | azuki-fileserver01 | Registry Persistence | Created "FileShareSync" Run key pointing to svchost.ps1 | T1547.001, T1036.005 |

---

### Phase 9: Anti-Forensics & Cleanup (2:26 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 2:26:01 AM | azuki-fileserver01 | History Deletion | Deleted ConsoleHost_history.txt | T1070.003 |
| 2:26:23 AM | azuki-fileserver01 | Tool Cleanup | Deleted pd.exe from staging directory | T1070.004 |

---

## Visual Timeline

```
12:27 AM   Return Access (RDP to azuki-sl from 159.26.106.98)
    │
    ▼
12:38 AM   Lateral Movement (RDP to azuki-fileserver01)
    │
    ▼
12:40 AM   Discovery Phase (whoami, net user, net share, ipconfig)
    │
    ▼
12:55 AM   Staging Setup (Hide directory, download scripts)
    │
    ▼
1:07 AM    Data Collection (xcopy from FileShares)
    │
    ▼
1:27 AM    Data Compression (tar archives)
    │
    ▼
1:59 AM    Data Exfiltration (curl to file.io)
    │
    ▼
2:03 AM    Credential Access (ProcDump LSASS)
    │
    ▼
2:10 AM    Persistence (Registry Run key)
    │
    ▼
2:26 AM    Anti-Forensics (Delete history, delete tools)
```

---

## Attack Phases Summary

| Phase | Time Window | Duration | Key Activities |
|-------|-------------|----------|----------------|
| Return Access | 12:27 AM | ~1 min | RDP from new external IP |
| Lateral Movement | 12:38 AM | ~2 min | Move to file server |
| Discovery | 12:40 - 12:42 AM | ~3 min | Enumerate users, shares, privileges, network |
| Staging Setup | 12:55 - 1:02 AM | ~7 min | Hide directory, download tools |
| Data Collection | 1:07 - 1:41 AM | ~34 min | Copy and compress sensitive data |
| Exfiltration | 1:59 - 2:00 AM | ~1 min | Upload to file.io (4 archives) |
| Credential Access | 2:03 - 2:24 AM | ~21 min | Deploy ProcDump, dump LSASS |
| Persistence | 2:10 AM | ~1 min | Create registry Run key |
| Anti-Forensics | 2:26 AM | ~1 min | Delete history and tools |

---

## Data Exfiltrated

| Archive | Contents | Size | Exfil Time |
|---------|----------|------|------------|
| credentials.tar.gz | IT-Admin-Passwords.csv and related files | Unknown | 1:59:54 AM |
| financial.tar.gz | Financial records | Unknown | 2:00:01 AM |
| contracts.zip | Business contracts | Unknown | 2:00:08 AM |
| shipping.tar.gz | Shipping information | Unknown | 2:00:20 AM |

---

## Key Observations

**Infrastructure Rotation:** The attacker used a different external IP (159.26.106.98) compared to the initial access (88.97.178.12), demonstrating operational security awareness to evade IP-based blocking.

**Tool Evolution:** Instead of using Mimikatz directly (as in Part 1), the attacker used ProcDump to create an LSASS memory dump. This is a stealthier approach that avoids running well-known credential dumping tools on the target.

**Rapid Exfiltration:** Four archives were exfiltrated within 26 seconds (1:59:54 AM - 2:00:20 AM), suggesting automated or scripted exfiltration.

**Methodical Cleanup:** The attacker deleted the PowerShell history file and the credential dumping tool before concluding operations, demonstrating anti-forensic discipline.

**Persistence Established:** Unlike Part 1 where persistence was via scheduled task, Part 2 used a registry Run key with a masqueraded filename (svchost.ps1), showing tactical variation.

**Critical Finding:** The discovery of IT-Admin-Passwords.csv stored in plaintext on a file share represents a significant security hygiene issue that directly enabled this phase of the attack.

---

## Comparison: Part 1 vs Part 2 Timeline

| Aspect | Part 1 (Nov 19) | Part 2 (Nov 22) |
|--------|-----------------|-----------------|
| Start Time | 6:36 PM | 12:27 AM |
| Duration | ~35 minutes | ~2 hours |
| Target System | azuki-sl | azuki-fileserver01 |
| External IP | 88.97.178.12 | 159.26.106.98 |
| Credential Tool | Mimikatz (mm.exe) | ProcDump (pd.exe) |
| Exfil Method | Discord webhook | file.io |
| Persistence | Scheduled task | Registry Run key |
| Log Clearing | Yes (wevtutil) | No |
| History Deletion | No | Yes |

---

## Notes

This timeline represents the complete attacker activity during Part 2 of the intrusion. The attacker completed their objectives on the file server within approximately 2 hours, demonstrating efficiency and familiarity with the target environment likely gained during Part 1 reconnaissance.

**Investigation Scope:** November 22 - December 6, 2025
