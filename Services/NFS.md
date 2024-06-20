**Nmap**
`EmaadAbbasi@htb[/htb]$ sudo nmap 172.16.1.5 -p111,2049 -sV -sC `
`EmaadAbbasi@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`

| **Command**                                               | **Description**                                  |
| --------------------------------------------------------- | ------------------------------------------------ |
| `showmount -e <FQDN/IP>`                                  | Show available NFS shares.                       |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share.umount ./target-NFS |
| `umount ./target-NFS`                                     | Unmount the specific NFS share.                  |
| `ls -l mnt/nfs/`                                          | List files with usernames and group names        |
| `ls -n mnt/nfs/`                                          | List files with UIDs and GUIDs                   |
|                                                           |                                                  |
