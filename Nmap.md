```
-sS : SYN Scan (TCP scan)
-sT : TCP Connect Scan
-sU : UDP Scan
-p : Specify port(s) to scan
-F : Fast mode, scans fewer ports (top 100)
-Pn : Disable ICMP Echo requests
-n : Disable DNS resolution
--disable-arp-ping : Disable ARP ping
--packet-trace : Show all packets sent and received
--reason : Display the reason a port is in a particular state
--stats-every=5s : Shows the progress of the scan every 5 seconds.
-sV : Perform a service version scan
-A : Agressive scan
--initial-rtt-timeout 50ms	Sets the specified time value as initial RTT timeout.
--max-rtt-timeout 100ms	Sets the specified time value as maximum RTT timeout.
--max-retries 0	Sets the number of retries that will be performed during the scan.
--min-rate 300	Sets the minimum number of packets to be sent per second.
-T 5	Specifies the insane timing template.
-D RND:5	Generates five random IP addresses that indicates the source IP the connection comes from.
--source-port 53	Performs the scans from specified source port.
```

The --packet-trace option provides detailed information about the packets exchanged during the scan.

The --reason option helps to understand the reason a port is in a particular state.


## Host Discovery

```
XeroCyb3r@htb[/htb]$ sudo nmap 10.10.110.0/24 -sn -oA tnet | grep for | cut -d" " -f5
XeroCyb3r@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
0x4ns3nic@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
0x4ns3nic@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host 
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 
```

- https://nmap.org/book/host-discovery-strategies.html  

## **Host and Port Scanning**


| State              | Description                                                                                                                                                                                             |     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `open`             | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations.                                      |     |
| `closed`           | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an `RST` flag. This scanning method can also be used to determine if our target is alive or not. |     |
| `filtered`         | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.                  |     |
| `unfiltered`       | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.                                               |     |
| `open\|filtered`   | If we do not get a response for a specific port, `Nmap` will set it to that state. This indicates that a firewall or packet filter may protect the port.                                                |     |
| `closed\|filtered` | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.                                               |     |

```
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 --top-ports=10
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -F -sU
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason
0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV
```

Normal output (-oN) with the .nmap file extension
Grepable output (-oG) with the .gnmap file extension
XML output (-oX) with the .xml file extension
We can also specify the option (-oA) to save the results in all formats. 

`0x4ns3nic@htb[/htb]$ xsltproc target.xml -o target.html`

- https://nmap.org/book/man-port-scanning-techniques.html

**Service enumeration**

`[!bash!]$  nc -nv 10.129.2.28 25`

`[!bash!]$ sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
`


**Nmap Scripting Engine**

| Category    | Description                                                                                                                             |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`      | Determination of authentication credentials.                                                                                            |
| `broadcast` | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute`     | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| `default`   | Default scripts executed by using the `-sC` option.                                                                                     |
| `discovery` | Evaluation of accessible services.                                                                                                      |
| `dos`       | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| `exploit`   | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| `external`  | Scripts that use external services for further processing.                                                                              |
| `fuzzer`    | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| `intrusive` | Intrusive scripts that could negatively affect the target system.                                                                       |
| `malware`   | Checks if some malware infects the target system.                                                                                       |
| `safe`      | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| `version`   | Extension for service detection.                                                                                                        |
| `vuln`      | Identification of specific vulnerabilities.                                                                                             |

```
0x4ns3nic@htb[/htb]$ sudo nmap <target> -sC
0x4ns3nic@htb[/htb]$ sudo nmap <target> --script <category>
0x4ns3nic@htb[/htb]$ sudo nmap <target> --script <script-name>,<script-name>,...
```

- https://nmap.org/nsedoc/index.html
- [Nmap Perfomance](https://nmap.org/book/man-performance.html)

## Evasion

`0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0`

`0x4ns3nic@htb[/htb]$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53`

`0x4ns3nic@htb[/htb]$ ncat -nv --source-port 53 10.129.2.28 50000`

