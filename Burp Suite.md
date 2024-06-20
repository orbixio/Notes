
| **Shortcut**     | **Description**  |
| ---------------- | ---------------- |
| [`CTRL+R`]       | Send to repeater |
| [`CTRL+SHIFT+R`] | Go to repeater   |
| [`CTRL+I`]       | Send to intruder |
| [`CTRL+SHIFT+I`] | Go to intruder   |
| [`CTRL+U`]       | URL encode       |
| [`CTRL+SHIFT+U`] | URL decode       |

In Burp, we can enable response interception by going to (`Proxy>Options`) and enabling `Intercept Response` under `Intercept Server Responses`.

##### **Automatic Request Modification**
We can go to (`Proxy>Options>Match and Replace`) and click on `Add` in Burp.

##### **Encoding/Decoding**
To URL-encode text in Burp Repeater, we can select that text and right-click on it, then select (`Convert Selection>URL>URL encode key characters`), or by selecting the text and clicking [`CTRL+U`]. Burp also supports URL-encoding as we type if we right-click and enable that option, which will encode all of our text as we type it.

In recent versions of Burp, we can also use the `Burp Inspector` tool to perform encoding and decoding (among other things), which can be found in various places like `Burp Proxy` or `Burp Repeater`

To access the full encoder in Burp, we can go to the `Decoder` tab.


##### **Proxying Tools**

To use `proxychains`, we first have to edit `/etc/proxychains.conf`
Add:
```shell-session
http 127.0.0.1 8080
```

```shell-session
Orbixio@htb[/htb]$ proxychains curl http://SERVER_IP:PORT
```

![](https://academy.hackthebox.com/storage/modules/110/proxying_proxychains_curl.jpg)


##### **Burp Scanner**

To start a scan in Burp Suite, we have the following options:

1. Start scan on a specific request from Proxy History
2. Start a new scan on a set of targets
3. Start a scan on items in-scope

##### **BApp Store**

To find all available extensions, we can click on the `Extender` tab within Burp and select the `BApp Store` sub-tab. Once we do this, we will see a host of extensions.

