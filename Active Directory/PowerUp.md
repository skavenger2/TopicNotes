# PowerUp

## Download

<https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1>

## Local Privilege Escalation

Non-exhaustive list  

```powershell
# Local queries only
Get-ServiceUnquoted -Verbose    # services without a quoted service path
Get-ModifiableServiceFile -Verbose    # edit a binary
Get-ModifiableService -Verbose    # modify service config

Invoke-AllChecks -Verbose    # all privesc checks

Invoke-ServiceAbuse   # modify vulnerbale service to create a local admin or execute a custom command
```

