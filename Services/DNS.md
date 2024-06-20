![](https://academy.hackthebox.com/storage/modules/27/tooldev-dns.png)

| **Command**                           | **Description**                                      |
| ------------------------------------- | ---------------------------------------------------- |
| `dig ns <domain.tld> @<nameserver>`   | NS request to the specific nameserver.               |
| `dig any <domain.tld> @<nameserver>`  | ANY request to the specific nameserver.              |
| `dig axfr <domain.tld> @<nameserver>` | AXFR request to the specific nameserver.             |
| `nslookup $TARGET`                    | Identify the `A` record for the target domain.       |
| `nslookup -query=PTR <IP>`            | Identify the `PTR` record for the target IP address. |
| `nslookup -query=ANY $TARGET`         | Identify `ANY` records for the target domain.        |
| `nslookup -query=TXT $TARGET`         | Identify the `TXT` records for the target domain.    |
| `nslookup -query=MX $TARGET`          | Identify the `MX` records for the target domain.     |



**Brute forcing**
```
Orbixio@htb[/htb]$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

# Now this subdomains.txt can be used for further dns enumeration 

dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>
```

**Gobuster DNS**

```shell-session
Orbixio@htb[/htb]$ export TARGET="facebook.com"
Orbixio@htb[/htb]$ export NS="d.ns.facebook.com"
Orbixio@htb[/htb]$ export WORDLIST="numbers.txt"
Orbixio@htb[/htb]$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

**Patterns**
```shell-session
lert-api-shv-{GOBUSTER}-sin6
atlas-pp-shv-{GOBUSTER}-sin6
```

**Subbrute**
```shell-session
Orbixio@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
Orbixio@htb[/htb]$ cd subbrute
Orbixio@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
Orbixio@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

**Zone Transfers**

For example, we will use the [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) service and the `zonetransfer.me` domain to have an idea of the information that can be obtained via this technique.

**Manual Approach**
```shell-session
# Get NameServers
Orbixio@htb[/htb]$ nslookup -type=NS zonetransfer.me

# Testing for ANY and AXFR Zone Transfers
Orbixio@htb[/htb]$ nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:

```shell-session
Orbixio@htb[/htb]# fierce --domain zonetransfer.me
```

**Domain Takeover**

We can find thousands of subdomains and domains on the web. Often they point to no longer active third-party service providers such as AWS, GitHub, and others and, at best, display an error message as confirmation of a deactivated third-party service. Large companies and corporations are also affected time and again. Companies often cancel services from third-party providers but forget to delete the associated DNS records. This is because no additional costs are incurred for a DNS entry. Many well-known bug bounty platforms, such as [HackerOne](https://www.hackerone.com/), already explicitly list `Subdomain Takeover` as a bounty category. With a simple search, we can find several tools on GitHub, for example, that automate the discovery of vulnerable subdomains or help create Proof of Concepts (`PoC`) that can then be submitted to the bug bounty program of our choice or the affected company. RedHuntLabs did a [study](https://redhuntlabs.com/blog/project-resonance-wave-1.html) on this in 2020, and they found that over 400,000 subdomains out of 220 million were vulnerable to subdomain takeover. 62% of them belonged to the e-commerce sector.

