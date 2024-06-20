`Orbixio@htb[/htb]$ telnet 10.10.11.14 25`

**Nmap**
`Orbixio@htb[/htb]$ sudo nmap 10.129.14.128 -sC -sV -p25`
`Orbixio@htb[/htb]$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`

**User Enumeration**
https://github.com/cytopia/smtp-user-enum

`smtp-user-enum -m EXPN -U /usr/share/wordlists/metasploit/unix_users.txt mail.example.tld 25`

- https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith2.txt
- https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt

| **Command**  | **Description**                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`       | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`  | The client names the email sender.                                                               |
| `RCPT TO`    | The client names the email recipient.                                                            |
| `DATA`       | The client initiates the transmission of the email.                                              |
| `RSET`       | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`       | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`       | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`       | The client terminates the session.                                                               |

One of the most recent publicly disclosed and dangerous [Simple Mail Transfer Protocol (SMTP)](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) vulnerabilities was discovered in [OpenSMTPD](https://www.opensmtpd.org/) up to version 6.6.2 service was in 2020. This vulnerability was assigned [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) and leads to RCE.