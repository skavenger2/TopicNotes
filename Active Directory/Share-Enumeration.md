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
```

## PowerView

Noisy  

```powershell
# With PowerView imported
Find-DomainShare
# OR
Invoke-ShareFinder
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
