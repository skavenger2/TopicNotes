# Red Team Enumeration

## Enumerating Domain

Current domain information
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

## PowerView Functions for the Local Machine

```txt
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

