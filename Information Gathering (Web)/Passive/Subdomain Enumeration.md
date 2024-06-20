
```shell-session
Orbixio@htb[/htb]$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```shell-session
Orbixio@htb[/htb]$ export TARGET="facebook.com"
Orbixio@htb[/htb]$ cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```

```shell-session
Orbixio@htb[/htb]$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```


==Custom Wordlist Generation==
`0x4ns3nic@htb[/htb]$ cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10`