| Command                                                                                                                                                         | Discription              |                   |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ----------------- |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`                                                                                                       | Directory Fuzzing        |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`                                                                                                  | Extension Fuzzing        |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`                                                                                              | Page Fuzzing             |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`                                                              | R                        | Directory Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`                                                                                                  | Extension Fuzzing        |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`                                                                                              | Page Fuzzing             |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`                                                              | Recursive Fuzzing        |                   |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`                                                                                                      | Sub-domain Fuzzing       |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://10.129.88.8/ -H 'Host: FUZZ.inlanefreight.local' -fs 15157`                                                                | VHost Fuzzing            |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`                                                                   | Parameter Fuzzing - GET  |                   |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |                   |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`       | Value fuzzing            |                   |
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`                                                                                                       | Add DNS entry            |                   |


We can even make it go faster if we are in a hurry by increasing the number of threads to 200, for example, with -t 200.
## Wordlists

| **Wordlists**                                                             | **Description**         |
| ------------------------------------------------------------------------- | ----------------------- |
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt`           | Extensions Wordlist     |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`      | Domain Wordlist         |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`     | Parameters Wordlist     |



#### Custom Wordlist Generation
`0x4ns3nic@htb[/htb]$ cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10`