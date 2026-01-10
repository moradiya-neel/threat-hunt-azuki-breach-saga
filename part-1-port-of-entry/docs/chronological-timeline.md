# AZUKI BREACH Threat Hunt - Part 1: Attack Timeline

This document provides a chronological timeline of the JADE SPIDER intrusion at Azuki Import/Export Trading Co., reconstructed from Azure Log Analytics logs during the Part 1 investigation.

---

## Timeline Overview

**Attack Date:** November 19, 2025

**Total Active Time:** Approximately 35 minutes (6:36 PM - 7:11 PM)

**Scope:** `azuki-sl` (IT admin workstation)

---

## Detailed Timeline

### Phase 1: Initial Access (6:36 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 6:36:18 PM | RDP Connection | Attacker connects from external IP 88.97.178.12 using compromised kenji.sato credentials | T1133, T1078 |

---

### Phase 2: Execution & Defence Evasion (6:37 PM - 6:49 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 6:37:40 PM | Script Download | PowerShell downloads wupdate.ps1 from http://78.141.196.6:8080 to Temp folder | T1059.001 |
| 6:37:41 PM | Script Execution | wupdate.ps1 executed with -WindowStyle Hidden -ExecutionPolicy Bypass | T1059.001 |
| 6:46:27 PM | Script Download | Downloads wupdate.bat from attacker-controlled server | T1059.001 |
| 6:49:27 PM | Defender Exclusion | Adds path exclusion: C:\Users\KENJI~1.SAT\AppData\Local\Temp | T1562.001 |
| 6:49:27 PM | Defender Exclusion | Adds path exclusion: C:\ProgramData\WindowsCache | T1562.001 |
| 6:49:27 PM | Defender Exclusion | Adds extension exclusion: .bat | T1562.001 |
| 6:49:27 PM | Defender Exclusion | Adds extension exclusion: .ps1 | T1562.001 |
| 6:49:29 PM | Defender Exclusion | Adds extension exclusion: .exe | T1562.001 |

---

### Phase 3: Discovery (7:03 PM - 7:05 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:03:56 PM | Network Recon | Executes ipconfig /all to gather network configuration | T1016 |
| 7:04:01 PM | Network Recon | Executes arp -a to discover local network devices and MAC addresses | T1016 |
| 7:05:11 PM | Credential Enum | Executes cmdkey /list to enumerate stored credentials | T1550 |
| 7:05:33 PM | Create Staging | Creates and hides staging directory: attrib.exe +h +s C:\ProgramData\WindowsCache | T1074.001, T1564.001 |

---

### Phase 4: Tool Deployment (7:06 PM - 7:07 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:06:58 PM | Malware Download | certutil.exe downloads svchost.exe to staging directory | T1105, T1218 |
| 7:07:21 PM | Tool Download | certutil.exe downloads AdobeGC.exe and saves as mm.exe (Mimikatz) | T1105, T1218 |
| 7:07:46 PM | Persistence | Creates scheduled task "Windows Update Check" to run malware daily at 2:00 AM as SYSTEM | T1053.005 |
| 7:07:52 PM | Verification | Queries scheduled task to verify persistence was established | T1053.005 |

---

### Phase 5: Credential Access (7:08 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:08:26 PM | Credential Theft | Executes mm.exe (Mimikatz) with sekurlsa::logonpasswords to dump credentials from LSASS | T1003.001 |

---

### Phase 6: Collection & Exfiltration (7:09 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:09:21 PM | Data Exfiltration | Uses curl.exe to upload export-data.zip to Discord webhook | T1567 |
| 7:09:48 PM | Backdoor Account | Creates local account "support" with net.exe user support /add | T1136.001 |
| 7:09:53 PM | Privilege Escalation | Adds "support" to Administrators group | T1098 |
| 7:09:57 PM | Verification | Queries support account to verify creation | T1136.001 |

---

### Phase 7: Lateral Movement (7:10 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:10:37 PM | Credential Storage | Uses cmdkey.exe to store fileadmin credentials for 10.1.0.188 | T1550 |
| 7:10:41 PM | Lateral Movement | Initiates RDP connection to 10.1.0.188 using mstsc.exe | T1021.001 |

---

### Phase 8: Command & Control + Anti-Forensics (7:11 PM)

| Timestamp | Activity | Details | MITRE ATT&CK |
|-----------|----------|---------|--------------|
| 7:11:04 PM | C2 Communication | Malicious svchost.exe establishes connection to 78.141.196.6:443 | T1071.001 |
| 7:11:39 PM | Log Clearing | Clears Security event log with wevtutil.exe cl Security | T1070.001 |
| 7:11:43 PM | Log Clearing | Clears System event log with wevtutil.exe cl System | T1070.001 |
| 7:11:46 PM | Log Clearing | Clears Application event log with wevtutil.exe cl Application | T1070.001 |

---

## Visual Timeline

```
6:36 PM    Initial Access (RDP from 88.97.178.12)
    │
    ▼
6:37 PM    Script Download & Execution (wupdate.ps1)
    │
    ▼
6:49 PM    Defence Evasion (Defender exclusions added)
    │
    ▼
7:03 PM    Discovery (ipconfig, arp -a)
    │
    ▼
7:05 PM    Staging Setup (Hidden directory created)
    │
    ▼
7:06 PM    Tool Deployment (certutil downloads malware)
    │
    ▼
7:07 PM    Persistence (Scheduled task created)
    │
    ▼
7:08 PM    Credential Access (Mimikatz execution)
    │
    ▼
7:09 PM    Exfiltration + Backdoor (Discord upload, support account)
    │
    ▼
7:10 PM    Lateral Movement (RDP to 10.1.0.188)
    │
    ▼
7:11 PM    C2 + Anti-Forensics (Connection established, logs cleared)
```

---

## Attack Phases Summary

| Phase | Time Window | Duration | Key Activities |
|-------|-------------|----------|----------------|
| Initial Access | 6:36 PM | ~1 min | RDP connection with stolen credentials |
| Execution & Evasion | 6:37 - 6:49 PM | ~12 min | Script execution, Defender exclusions |
| Discovery | 7:03 - 7:05 PM | ~2 min | Network enumeration, credential listing |
| Tool Deployment | 7:06 - 7:07 PM | ~2 min | Malware download, persistence setup |
| Credential Access | 7:08 PM | ~1 min | Mimikatz credential dump |
| Collection & Exfil | 7:09 PM | ~1 min | Data exfiltration, backdoor creation |
| Lateral Movement | 7:10 PM | ~1 min | RDP to secondary target |
| C2 & Cleanup | 7:11 PM | ~1 min | C2 connection, log clearing |

---

## Key Observations

**Speed of Execution:** The attacker completed the entire attack chain in approximately 35 minutes, demonstrating a high level of preparation and likely scripted/automated operations. This aligns with JADE SPIDER's known use of automated attack scripts.

**Methodical Approach:** The attacker followed a logical sequence, ensuring each phase was complete before moving to the next. This includes verification steps such as querying the scheduled task after creation and checking the support account after creation.

**Anti-Forensics Priority:** The Security log was cleared first, indicating the attacker prioritized removing evidence of authentication events over other log types.

**Persistence Redundancy:** The attacker established multiple persistence mechanisms, including a scheduled task running as SYSTEM and a backdoor administrator account, ensuring continued access even if one mechanism is discovered.

---

## Notes

This timeline represents activity observed on `azuki-sl` only. The lateral movement to 10.1.0.188 occurred at 7:10 PM, and activity on that secondary system will be covered in subsequent parts of this threat hunt series.

**Investigation Scope:** November 1 - November 22, 2025
