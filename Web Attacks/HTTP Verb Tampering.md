```shell-session
Orbixio@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/
```

Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application.
The first type of HTTP Verb Tampering vulnerability is mainly caused by `Insecure Web Server Configurations`, and exploiting this vulnerability can allow us to bypass the HTTP Basic Authentication prompt on certain pages.

To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then use `Change Request Method` to change it to another method

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_GET_request.jpg)
