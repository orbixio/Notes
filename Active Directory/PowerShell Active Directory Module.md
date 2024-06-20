```
Import-Module ActiveDirectory
```

| Command                                                                                  | Purpose                                                                 |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `Get-ADDomain`                                                                           | Retrieves information about the Active Directory domain.                |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | Retrieves Active Directory users with non-null Service Principal Names. |
| `Get-ADTrust -Filter *`                                                                  | Retrieves information about all Active Directory trusts.                |
| `Get-ADGroup -Filter * \| select name`                                                   | Retrieves names of all Active Directory groups.                         |
| `Get-ADGroup -Identity "Backup Operators"`                                               | Retrieves information about the "Backup Operators" group.               |
