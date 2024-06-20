```shell-session
Orbixio@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
Orbixio@htb[/htb]$ cat mut_password.list
```
==Existing Rules==
```shell-session
Orbixio@htb[/htb]$ ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```
==Generating Wordlists Using CeWL==
```shell-session
Orbixio@htb[/htb]$ cewl http://10.10.110.100:65000/wordpress/index.php/languages-and-frameworks/ -d 4 -m 6 --lowercase -w inlane.wordlist
Orbixio@htb[/htb]$ wc -l inlane.wordlist
```