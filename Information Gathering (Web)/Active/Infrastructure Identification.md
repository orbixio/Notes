==Identify Infrastructure==

```shell-session
Orbixio@htb[/htb]$ curl -I http://${TARGET}
```

**X-Powered-By header**: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

**Cookies**: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
    
    - .NET: `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
    - PHP: `PHPSESSID=<COOKIE_VALUE>`
    - JAVA: `JSESSION=<COOKIE_VALUE>`

```shell-session
Orbixio@htb[/htb]$ whatweb -a3 https://www.facebook.com -v
```

You could also use [Wappalyzer](https://www.wappalyzer.com/).

==Identify Waf==
```shell-session
Orbixio@htb[/htb]$ wafw00f -v https://www.tesla.com
```

==Aquatone==

```shell-session
Orbixio@htb[/htb]$ cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```
