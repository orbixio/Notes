```
# Check which remote access methods are accessible

nmap -sC -sV --disable-arp-ping -n -p3389,5985,5986,135  $_ip
```

## [[RDP]]
## WinRm

==Nmap==
```
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

==Interaction==
```
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

```powershell-session
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

`Test-WSMan` CMD-Let can be used to enumerate WinRM Service on a windows machine.
Documentation is avail at this [page](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman?view=powershell-7.2).
==Brute Forcing==
```shell-session
Orbixio@htb[/htb]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

## WMI


==Nmap==
```
nmap -sV -sC $_ip -p135 --disable-arp-ping -n
```

==Interaction==
```
/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
