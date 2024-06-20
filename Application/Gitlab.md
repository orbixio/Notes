==Footprinting and Discovery==

The only way to footprint the GitLab version number in use is by browsing to the /help page when logged in.

==Enumeration==

The first thing we should try is browsing to /explore and see if there are any public projects that may contain something interesting.

**Userenum**

- https://www.exploit-db.com/exploits/49821
- https://github.com/dpgg101/GitLabUserEnum

GitLab's defaults are set to 10 failed attempts resulting in an automatic unlock after 10 minutes. 

`[!bash!]$ gitlab_userenum.py --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt`

- Weak Creds: `Welcome1` and `Password123`
