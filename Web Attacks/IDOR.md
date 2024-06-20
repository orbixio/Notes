The main takeaway is that `an IDOR vulnerability mainly exists due to the lack of an access control on the back-end`.

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

Places to look for IDOR:
- URL Parameters & APIs
- AJAX Calls

You can exploit IDOR with help of `Burp Intruder`

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uid_mismatch.jpg)
