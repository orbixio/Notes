==SSH-audit==

```
Orbixio@htb[/htb]$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
Orbixio@htb[/htb]$ ./ssh-audit.py 10.129.14.132
```

==Change Authentication Method==
```
Orbixio@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132       # To get avail. methods of auth

Orbixio@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```
==Brute Forcing==
```shell-session
Orbixio@htb[/htb]$ hydra -L user.list -P password.list ssh://10.129.42.197
```

## ==Rsync==

```shell-session
Orbixio@htb[/htb]$ sudo nmap -sV -p 873 127.0.0.1
```

==Probing for accessible shares==

```
Orbixio@htb[/htb]$ nc -nv 127.0.0.1 873
```
==Enumerating an Open Share==

```
Orbixio@htb[/htb]$ rsync -av --list-only rsync://127.0.0.1/dev
```

If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH. This [guide](https://phoenixnap.com/kb/how-to-rsync-over-ssh) is helpful for understanding the syntax for using Rsync over SSH.

**==Scanning for R-services==**

`Orbixio@htb[/htb]$ sudo nmap -sV -p 512,513,514 10.0.17.2`

 R-services are less frequently used nowadays due to their inherent security flaws and the availability of more secure protocols such as SSH.

If however you find it in a pentest refer to this [page](https://academy.hackthebox.com/module/112/section/1240). 
