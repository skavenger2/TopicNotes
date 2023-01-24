# Options to Map Share Drives

## NET

```cmd
# For remote machines   -    These can fail due to AV or firewalls
net view \\192.168.1.17 /All
net view /domain
# For the local machine
net share
```

## Powershell

Quiet  

```powershell
# Local shares
get-smbshare
Get-WmiObject -Class win32_share
```

## PowerView

Noisy  

```powershell
# With PowerView imported
Find-DomainShare
# OR
Invoke-ShareFinder -Verbose    # find shares on hosts in current domain   # LDAP lookup
Invoke-FileFinder -Verbose    # find sensitive files on computers in the domain   # LDAP lookup
Get-NetFileServer -Verbose    # find fileservers in the domain    # LDAP lookup
```

## CrackMapExec

Downlaod CME binaries from <https://github.com/Porchetta-Industries/CrackMapExec/releases>  
Appears to be similar to standard smbclient connections  

```powershell
# Multiple options
cme smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --shares
cme smb 192.168.1.1 -u UserName -p 'PASSWORDHERE' --shares
cme smb 192.168.1.0-15 -u UserName -p 'PASSWORDHERE' --shares
```
