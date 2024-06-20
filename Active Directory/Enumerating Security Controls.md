```powershell-session
PS C:\htb> Get-MpComputerStatus
```
**Note:** If `RealTimeProtectionEnabled` is set to `True` then `Defender` is on alert!

```powershell-session
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PS C:\htb> $ExecutionContext.SessionState.LanguageMode
```
##### LAPS
The Microsoft [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
```
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll
```

```powershell-session
PS C:\htb> Find-LAPSDelegatedGroups
```

> [!NOTE] Delegated Groups
> The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups

```powershell-session
PS C:\htb> Find-AdmPwdExtendedRights
PS C:\htb> Get-LAPSComputers
```

```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```

```
nxc smb <ip> -u user-can-read-laps -p pass --laps
```