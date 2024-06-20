[Netcraft](https://www.netcraft.com/) can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view. We can use the service by visiting `https://sitereport.netcraft.com` and entering the target domain.

The [Internet Archive](https://en.wikipedia.org/wiki/Internet_Archive) is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

We can access several versions of these websites using the [Wayback Machine](http://web.archive.org/) to find old versions that may have interesting comments in the source code or files that should not be there.

```shell-session
Orbixio@htb[/htb]$ waybackurls -dates https://facebook.com > waybackurls.txt
Orbixio@htb[/htb]$ cat waybackurls.txt
```

![](https://academy.hackthebox.com/storage/modules/144/wayback1.png)