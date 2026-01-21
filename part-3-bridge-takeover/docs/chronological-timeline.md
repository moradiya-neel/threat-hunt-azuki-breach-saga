# AZUKI BREACH Threat Hunt - Part 3: Attack Timeline

This document provides a chronological timeline of the JADE SPIDER intrusion during Part 3 of the investigation, focusing on the attacker's activity on the CEO's administrative PC (azuki-adminpc) on November 2588, 2025.

---

## Timeline Overview

**Attack Date:** November 25, 2025

**Total Active Time:** Approximately 2 hours (4:06 AM - 6:10 AM)

**Dwell Time Since Initial Access:** ~6 days (from Nov 19, 6:36 PM)

**Dwell Time Since Part 2:** ~3 days (from Nov 22, 2:26 AM)

**Target System:** azuki-adminpc (CEO's administrative PC)

---

## Detailed Timeline

### Phase 1: Lateral Movement (4:06 AM - 4:07 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:06:41 AM | azuki-adminpc | RDP Logon | yuki.tanaka from 10.1.0.204 (AZUKI-SL) | T1021.001 |

---

### Phase 2: Discovery (4:08 AM - 4:15 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:08:58 AM | azuki-adminpc | Session Enumeration | `qwinsta.exe` | T1033 |
| 4:09:07 AM | azuki-adminpc | User Enumeration | `quser.exe` | T1033 |
| 4:09:25 AM | azuki-adminpc | Domain Trust Enum | `nltest.exe /domain_trusts /all_trusts` | T1482 |
| 4:10:07 AM | azuki-adminpc | Network Connections | `NETSTAT.EXE -ano` | T1049 |
| 4:13:45 AM | azuki-adminpc | Password DB Search | `where /r C:\Users *.kdbx` | T1552.001 |
| 4:15:52 AM | azuki-adminpc | Credential File Access | Opened OLD-Passwords.txt | T1552.001 |

---

### Phase 3: Malware Deployment (4:21 AM - 4:24 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:21:11 AM | azuki-adminpc | Malware Download | `curl.exe` downloads KB5044273-x64.7z from catbox.moe | T1105 |
| 4:21:32 AM | azuki-adminpc | Archive Extraction | `7z.exe` extracts password-protected archive | T1140 |
| 4:21:33 AM | azuki-adminpc | Tools Extracted | m.exe, meterpreter.exe, silentlynx.exe created | T1105 |
| 4:24:35 AM | azuki-adminpc | C2 Established | Named pipe msf-pipe-5902 created by meterpreter.exe | T1090.001 |

---

### Phase 4: Data Collection (4:28 AM - 4:40 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:28:09 AM | azuki-adminpc | Copy QuickBooks | `Robocopy.exe` to staging directory | T1119 |
| 4:37:03 AM | azuki-adminpc | Copy Banking | `Robocopy.exe` Banking folder | T1119 |
| 4:37:22 AM | azuki-adminpc | Copy Tax Records | `Robocopy.exe` Tax-Records folder | T1119 |
| 4:37:33 AM | azuki-adminpc | Stage Tax Docs | Tax-Supporting-Docs-2024.zip | T1074.001 |
| 4:37:38 AM | azuki-adminpc | Copy Contracts | `Robocopy.exe` Contracts folder | T1119 |
| 4:37:49 AM | azuki-adminpc | Stage Contracts 2022 | All-Contracts-2022.zip | T1074.001 |
| 4:38:01 AM | azuki-adminpc | Stage Contracts 2023 | All-Contracts-2023.zip | T1074.001 |
| 4:39:16 AM | azuki-adminpc | Archive Credentials | `tar.exe` creates credentials.tar.gz | T1560.001 |
| 4:39:23 AM | azuki-adminpc | Archive QuickBooks | `tar.exe` creates quickbooks-data.tar.gz | T1560.001 |
| 4:40:00 AM | azuki-adminpc | Archive Banking | `tar.exe` creates banking-records.tar.gz | T1560.001 |
| 4:40:13 AM | azuki-adminpc | Archive Tax Docs | `tar.exe` creates tax-documents.tar.gz | T1560.001 |
| 4:40:30 AM | azuki-adminpc | Archive Contracts | `tar.exe` creates contracts-data.tar.gz | T1560.001 |

---

### Phase 5: First Exfiltration Wave (4:41 AM - 4:49 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:41:51 AM | azuki-adminpc | Exfil Credentials | `curl.exe` uploads credentials.tar.gz to gofile.io | T1567.002 |
| 4:42:04 AM | azuki-adminpc | Exfil QuickBooks | `curl.exe` uploads quickbooks-data.tar.gz | T1567.002 |
| 4:42:13 AM | azuki-adminpc | Exfil Banking | `curl.exe` uploads banking-records.tar.gz | T1567.002 |
| 4:42:23 AM | azuki-adminpc | Exfil Tax Docs | `curl.exe` uploads tax-documents.tar.gz | T1567.002 |
| 4:42:33 AM | azuki-adminpc | Exfil Contracts | `curl.exe` uploads contracts-data.tar.gz | T1567.002 |
| 4:48:25 AM | azuki-adminpc | Archive Chrome Creds | `tar.exe` creates chrome-credentials.tar.gz | T1560.001 |
| 4:49:19 AM | azuki-adminpc | Exfil Chrome Creds | `curl.exe` uploads chrome-credentials.tar.gz | T1567.002 |

---

### Phase 6: Persistence (4:51 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 4:51:08 AM | azuki-adminpc | Create Backdoor Account | Encoded: `net user yuki.tanaka2 B@ckd00r2024! /add` | T1136.001 |
| 4:51:23 AM | azuki-adminpc | Elevate Backdoor | Encoded: `net localgroup Administrators yuki.tanaka2 /add` | T1098 |

---

### Phase 7: Additional Credential Theft (5:55 AM - 5:58 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 5:55:34 AM | azuki-adminpc | Download Mimikatz | `curl.exe` downloads m-temp.7z from catbox.moe | T1105 |
| 5:55:44 AM | azuki-adminpc | Extract Mimikatz | `7z.exe` extracts m.exe | T1140 |
| 5:55:54 AM | azuki-adminpc | Chrome Theft | `m.exe dpapi::chrome` extracts Chrome passwords | T1555.003 |
| 5:56:42 AM | azuki-adminpc | Archive Session Data | `tar.exe` creates chrome-session-theft.tar.gz | T1560.001 |
| 5:56:50 AM | azuki-adminpc | Exfil Session Data | `curl.exe` uploads chrome-session-theft.tar.gz | T1567.002 |
| 5:57:02 AM | azuki-adminpc | Delete Mimikatz | m.exe deleted (anti-forensics) | T1070.004 |
| 5:58:27 AM | azuki-adminpc | Download PsExec | PsExec64.exe from live.sysinternals.com | T1105 |

---

### Phase 8: Additional RDP Sessions (6:06 AM - 6:10 AM)

| Timestamp | Device | Activity | Details | MITRE ATT&CK |
|-----------|--------|----------|---------|--------------|
| 6:06:55 AM | azuki-adminpc | RDP Session | Additional logon from AZUKI-SL | T1021.001 |
| 6:10:41 AM | azuki-adminpc | Cleanup | PsExec64.exe deleted | T1070.004 |

---

## Visual Timeline

```
4:06 AM    Lateral Movement (RDP from AZUKI-SL)
    │
    ▼
4:08 AM    Discovery Phase (qwinsta, quser, nltest, netstat)
    │
    ▼
4:13 AM    Credential Discovery (KeePass search, OLD-Passwords.txt)
    │
    ▼
4:21 AM    Malware Deployment (curl → 7z → meterpreter.exe)
    │
    ▼
4:24 AM    C2 Established (msf-pipe-5902)
    │
    ▼
4:28 AM    Data Collection (Robocopy QuickBooks, Banking, Tax, Contracts)
    │
    ▼
4:39 AM    Data Compression (tar.exe creates archives)
    │
    ▼
4:41 AM    First Exfiltration Wave (5 archives to gofile.io)
    │
    ▼
4:48 AM    Chrome Credential Theft & Exfil
    │
    ▼
4:51 AM    Persistence (yuki.tanaka2 backdoor account)
    │
    ▼
5:55 AM    Second Credential Theft (Mimikatz dpapi::chrome)
    │
    ▼
5:56 AM    Session Data Exfiltration
    │
    ▼
5:57 AM    Anti-Forensics (delete m.exe)
    │
    ▼
6:10 AM    Final Cleanup (delete PsExec64.exe)
```

---

## Attack Phases Summary

| Phase | Time Window | Duration | Key Activities |
|-------|-------------|----------|----------------|
| Lateral Movement | 4:06 AM | ~1 min | RDP from AZUKI-SL |
| Discovery | 4:08 - 4:15 AM | ~7 min | Session, domain, network, password enumeration |
| Malware Deployment | 4:21 - 4:24 AM | ~3 min | Download, extract, execute toolkit |
| Data Collection | 4:28 - 4:40 AM | ~12 min | Robocopy and tar.exe operations |
| Exfiltration Wave 1 | 4:41 - 4:49 AM | ~8 min | 6 archives to gofile.io |
| Persistence | 4:51 AM | ~1 min | Backdoor account creation |
| Credential Theft | 5:55 - 5:57 AM | ~2 min | Chrome password extraction |
| Exfiltration Wave 2 | 5:56 AM | ~1 min | Chrome session data |
| Cleanup | 5:57 - 6:10 AM | ~13 min | Tool deletion |

---

## Data Exfiltrated

| Archive | Contents | Exfil Time | Destination |
|---------|----------|------------|-------------|
| credentials.tar.gz | KeePass DB + Master Password | 4:41:51 AM | gofile.io |
| quickbooks-data.tar.gz | Accounting data | 4:42:04 AM | gofile.io |
| banking-records.tar.gz | Banking documents | 4:42:13 AM | gofile.io |
| tax-documents.tar.gz | Tax records | 4:42:23 AM | gofile.io |
| contracts-data.tar.gz | Business contracts | 4:42:33 AM | gofile.io |
| chrome-credentials.tar.gz | Browser passwords | 4:49:19 AM | gofile.io |
| chrome-session-theft.tar.gz | Browser cookies | 5:56:50 AM | gofile.io |

**Total Archives Exfiltrated:** 7

---

## Key Observations

**Sophisticated Toolkit:** Unlike Parts 1 and 2, which relied primarily on living-off-the-land techniques, Part 3 introduced a full offensive toolkit including Meterpreter (Metasploit), custom JADE SPIDER implant (silentlynx.exe), and Mimikatz.

**Threat Actor Attribution:** The presence of `silentlynx.exe` provides direct attribution to JADE SPIDER, as "SilentLynx" is a known alias for this threat actor.

**Rapid Exfiltration:** Seven archives were exfiltrated across two waves, with the first wave completing in under 8 minutes.

**Anti-Forensic Discipline:** Tools (m.exe, PsExec64.exe) were deleted after use, minimizing forensic artifacts.

**Password Manager Failure:** The discovery and exfiltration of both the KeePass database and its master password represent a catastrophic security failure.

**Browser Credential Focus:** Two separate operations targeted Chrome credentials; first, the login database, and then session cookies for potential session hijacking.

---

## Comparison: Timeline Across All Parts

| Aspect | Part 1 (Nov 19) | Part 2 (Nov 22) | Part 3 (Nov 25) |
|--------|-----------------|-----------------|-----------------|
| Start Time | 6:36 PM | 12:27 AM | 4:06 AM |
| Duration | ~35 minutes | ~2 hours | ~2 hours |
| Target System | AZUKI-SL | azuki-fileserver01 | azuki-adminpc |
| Account Used | kenji.sato | fileadmin | yuki.tanaka |
| Credential Tool | Mimikatz (mm.exe) | ProcDump (pd.exe) | Mimikatz (m.exe) |
| Exfil Method | Discord webhook | file.io | gofile.io |
| Archives Exfil | 1 | 4 | 7 |
| C2 Implant | svchost.exe | svchost.ps1 | meterpreter.exe |
| Custom Implant | No | No | silentlynx.exe |

---

## Notes

This timeline represents the complete activity of the attacker during Part 3 of the intrusion. The attacker demonstrated significant evolution in tactics, deploying professional penetration testing tools and a custom implant while maintaining operational security through tool rotation and anti-forensic cleanup.

**Investigation Scope:** November 24 - December 6, 2025
