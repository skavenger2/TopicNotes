# Options to Enumerate Users

## Net

```cmd
# Query the current domain DC
net user /domain

# Enumerate specific user
net user <username /domain

# Local users
net user
```

## Powershell

Quiet  
<https://0xinfection.github.io/posts/wmi-recon-enum/>  
<https://0xinfection.github.io/posts/wmi-ad-enum/>  

```powershell
# Local users
Get-WmiObject -ComputerName workstation1 -Class Win32_UserAccount -Filter "LocalAccount=True"

# domain users
Get-WmiObject -Class win32_useraccount
# users and which domain they belong to
Get-WmiObject -Class win32_useraccount | select name, domain, accounttype


# domain groups
Get-WmiObject -Class win32_group

```

## PowerView

Noisy  

```powershell
# With PowerView imported
Get-DomainUser    # LDAP query
Get-DomainGroup   # LDAP query
Get-NetUser       # LDAP query

Find-LocalAdminAccess   # LDAP query
Invoke-EnumerateLocalAdmin    # LDAP query
Invoke-UserHunter   # LDAP query
```

## CrackMapExec

Queries the domain

```powershell
# Different options
cme smb 192.168.215.104 -u 'user' -p 'PASS' --users
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --users

# Query local users
cme smb 192.168.215.104 -u 'user' -p 'PASS' --local-users
```
