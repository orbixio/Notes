**Nmap**
`EmaadAbbasi@htb[/htb]$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC`

| **Command**                                                                   | **Description**                         |
| ----------------------------------------------------------------------------- | --------------------------------------- |
| `curl -k 'imaps://127.0.0.1' --user riley@painters.htb:PainterDBPassword2022` | Log in to the IMAPS service using cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps`                                   | Connect to the IMAPS service.           |
| `openssl s_client -connect 127.0.0.1:pop3s`                                   | Connect to the POP3s service.           |
**IMAP Commands**

| **Command**                     | **Description**                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LOGIN username password`     | User's login.                                                                                                 |
| `1 LIST "" *`                   | Lists all directories.                                                                                        |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                                                                      |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                                                                            |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                                                                            |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                                                      |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.                                                             |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                                                                   |

POP3 Commands

| **Command**     | **Description**                                             |
| --------------- | ----------------------------------------------------------- |
| `USER username` | Identifies the user.                                        |
| `PASS password` | Authentication of the user using its password.              |
| `STAT`          | Requests the number of saved emails from the server.        |
| `LIST`          | Requests from the server the number and size of all emails. |
| `RETR id`       | Requests the server to deliver the requested email by ID.   |
| `DELE id`       | Requests the server to delete the requested email by ID.    |
| `CAPA`          | Requests the server to display the server capabilities.     |
| `RSET`          | Requests the server to reset the transmitted information.   |
| `QUIT`          | Closes the connection with the POP3 server.                 |

**Evolution**
```
apt install evolution
```

![](https://book.hacktricks.xyz/~gitbook/image?url=https%3A%2F%2F129538173-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fassets%252F-L_2uGJGU7AVNRcqRvEi%252F-Mb1xJJ1ZjWJq6ycKv4z%252F-Mb3hPPkjUl22_NlZSyR%252Fimage.png%3Falt%3Dmedia%26token%3D7a66ec32-1e3a-4548-b981-fde510e5f0a7&width=768&dpr=1&quality=100&sign=2ea9942919b63d71e2039bd64e0f76f7c408fb71300ec1703e6b1c2564ff0fa7)


**Curl IMAPs Enum**
```
curl -k 'imaps://1.2.3.4/' --user user:pass
curl -k 'imaps://1.2.3.4/INBOX?ALL' --user user:pass
curl -k 'imaps://1.2.3.4/Drafts;MAILINDEX=1' --user user:pass
```
**Automate**
```
for m in {1..5}; do
  echo $m
  curl "imap://1.2.3.4/INBOX;MAILINDEX=$m;SECTION=HEADER.FIELDS%20(SUBJECT%20FROM)" --user user:pass
done
```