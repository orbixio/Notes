- [PayloadsAllTheThings - Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [HackTricks - SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [BlackHat](https://129538173-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-9eacd65568add9f7940b211234f677a2379af069%2FEN-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-BlackHat-15.pdf?alt=media)

```shell-session
Orbixio@htb[/htb]$ git clone https://github.com/epinna/tplmap.git
Orbixio@htb[/htb]$ cd tplmap
Orbixio@htb[/htb]$ pip install virtualenv
Orbixio@htb[/htb]$ virtualenv -p python2 venv
Orbixio@htb[/htb]$ source venv/bin/activate
Orbixio@htb[/htb]$ pip install -r requirements.txt
Orbixio@htb[/htb]$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john
```