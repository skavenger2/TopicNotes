# PowerView

## Downlaod

<https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>

## AD Recon

```powershell
# .NET classes
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()

Get-NetDomain -Domain moneycorp.local   # the .NET commands above are equal to PowerView's Get-NetDomain
Get-DomainSID   # LDAP lookup
Get-NetComputer   # LDAP lookup
Get-NetDomainController   # Possibly local query
Get-NetDomainTrust    # LDAP lookup
Get-NetForstTrust   # LDAP lookup
```

## User Recon

```powershell
# cmd.exe
net user /domain
net user /domain username   # replace 'username' with a username you want more details for

# PowerView
Get-NetUser   # LDAP lookup
Get-NetUser | select SamAccountName
Get-NetUser -Username name1

Get-NetGroup | select name   # list group names in domain   # LDAP lookup
Get-NetGroup 'Domain Admins'     # for a single group's info
Get-NetGroup '*admin*'     # same as above but for any group name that contains the keyword admin
# Groups such as 'Enterprise admins' are only available on the Forest root DC, ie. Get-NetGroup '*admin*' -Domain moneycorp.local
Get-NetGroup -Domain <targetdomain>     # for trusted domains
Get-NetGroup -FullData
```

## Share Recon

```powershell
# PowerView
Invoke-ShareFinder -Verbose    # find shares on hosts in current domain   # LDAP lookup
Invoke-FileFinder -Verbose    # find sensitive files on computers in the domain   # LDAP lookup
Get-NetFileServer -Verbose    # find fileservers in the domain    # LDAP lookup

## Alternate ##
# On Windows machine with PowerView:
Get-NetComputer | select SamAccountName
# On Linux machine
smbclient -N -L \\\\{machine name}\\
# With creds
smbclient -L \\\\{machine name}\\ -U {username} -P
```

## PowerView Functions for the Local Machine

```
Get-NetLocalGroup                   -   enumerates the local groups on the local (or remote) machine
Get-NetLocalGroupMember             -   enumerates members of a specific local group on the local (or remote) machine
Get-NetShare                        -   returns open shares on the local (or a remote) machine
Get-NetLoggedon                     -   returns users logged on the local (or a remote) machine
Get-NetSession                      -   returns session information for the local (or a remote) machine
Get-RegLoggedOn                     -   returns who is logged onto the local (or a remote) machine through enumeration of remote registry keys
Get-NetRDPSession                   -   returns remote desktop/session information for the local (or a remote) machine
Test-AdminAccess                    -   rests if the current user has administrative access to the local (or a remote) machine
Get-NetComputerSiteName             -   returns the AD site where the local (or a remote) machine resides
Get-WMIRegProxy                     -   enumerates the proxy server and WPAD conents for the current user
Get-WMIRegLastLoggedOn              -   returns the last user who logged onto the local (or a remote) machine
Get-WMIRegCachedRDPConnection       -   returns information about RDP connections outgoing from the local (or remote) machine
Get-WMIRegMountedDrive              -   returns information about saved network mounted drives for the local (or remote) machine
Get-WMIProcess                      -   returns a list of processes and their owners on the local or remote machine
Find-InterestingFile                -   searches for files on the given path that match a series of specified criteria
```

