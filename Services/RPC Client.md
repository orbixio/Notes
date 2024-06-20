`EmaadAbbasi@htb[/htb]$ rpcclient -U "" 10.129.14.128`

| **Query**                 | **Description**                                                    |
| ------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                 | Server information.                                                |
| `enumdomains`             | Enumerate all domains that are deployed in the network.            |
| `querydominfo`            | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`         | Enumerates all available shares.                                   |
| `netsharegetinfo <share>` | Provides information about a specific share.                       |
| `enumdomusers`            | Enumerates all domain users.                                       |
| `queryuser <RID>`         | Provides information about a specific user.                        |
| `querygroup <RID>`        | Provides information about a specific group.                       |

**Brute forcing User RIDs**

`EmaadAbbasi@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" solarlab.htb -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`

**Impacket - Samrdump.py**

`EmaadAbbasi@htb[/htb]$ impacket-samrdump 10.129.14.128`

**Enum4Linux-ng - Enumeration**

`EmaadAbbasi@htb[/htb]$ enum4linux-ng 10.129.14.128 -A`



