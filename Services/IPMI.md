**Version**
```
# Nmap
Orbixio@htb[/htb]$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
# Metasploit
msf6> use auxiliary/scanner/ipmi/ipmi_version
```

**Dump Hashes**
```
msf6> use auxiliary/scanner/ipmi/ipmi_dumphashes 
```

**Default Passwords**

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` which tries all combinations of upper case letters and numbers for an eight-character password.