```
$ fping -asgq 10.10.10.0/24
$ sudo nmap -p- --min-rate 1000 10.10.10.10
$ sudo nmap -p<ports go here> -sV -sC -A -T4 10.10.10.10 -oA CPTS/nmap/10.10.10.10
```
#### Vhost fuzzing
```
$ curl -I http://10.10.10.10
$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.10.110.35 -H "Host: FUZZ.painters.htb" -ac

# Always try the below one for maybe extra Vhosts
$ cewl -m5 --lowercase http://inlanefreight.local > cewl_output_inlanefreight_local.txt
$ ffuf -w cewl_output_inlanefreight_local.txt:FUZZ -u http://10.10.10.10 -H "Host: FUZZ.inlanefreight.local" -ac
```

> [!WARNING] Casing of the payload
> Always first check if the target website is case sensitive. 
#### Directory fuzzing

```
# First of all fuzz for extensions
$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://inlanefreight.local/indexFUZZ -ac 

$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt:FUZZ -u http://inlanefreight.local/FUZZ -e <extensions> -ac

# Also do the same with cewl_output file
$ ffuf -w cewl_output_inlanefreight_local.txt:FUZZ -u http://inlanefreight.local/FUZZ -e <extensions> -ac
```
You can also do `recursive` scanning using the flag `-recursion -recursion-depth 1`

> [!INFO] Repetition
> Repeat the above scan for all the `Vhosts`. You could also write a script that does this for you automatically.

#### Handy commands
```
$ evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
$ xfreerdp /v:10.10.10.10 /u:htb-student /p:password!

$ enum4linux-ng 10.10.10.10 -A
$ crackmapexec smb 10.10.10.10 -u '' -p '' --shares
$ crackmapexec smb 10.10.10.10 -u '' -p '' --rid-brute

$ wget -m --no-passive ftp://anonymous:anonymous@<target>

$ smtp-user-enum -m EXPN -U /usr/share/wordlists/metasploit/unix_users.txt mail.example.tld 25


$ snmpwalk -v2c -c <community string> <FQDN/IP>
$ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt <FQDN/IP>
$ braa <community string>@<FQDN/IP>:.1.*

$ ./odat.py all -s 10.129.204.235

$ showmount -e <FQDN/IP>
$ mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock

$ dig axfr <domain.tld> @<nameserver>
$ dig any <domain.tld> @<nameserver>
$ dig txt <domain.tld> @<nameserver>

$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
$ ./ssh-audit.py 10.129.14.132

$ wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

$ curl -k 'imaps://mailing.htb' --user user@inlanefreight.local:pass
$ openssl s_client -connect <FQDN/IP>:imaps
$ openssl s_client -connect 10.10.11.14:pop3s

$ mysql -u root -pHello -h 10.129.14.132

$ mssqlclient.py <user>@<FQDN/IP> -windows-auth
$ sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

$ whatweb -a3 https://www.facebook.com -v
$ nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```
