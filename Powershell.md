# Powershell Code Snippets

## Loop Over a List of Usernames and Find Their Active Status

```powershell
# Append each username in the list and their account status (active or not)

$list = cat .\userlist.txt
foreach ($item in $list)
{
  echo $item >> user_status.txt
  net user /domain $item | findstr /C:"Account active" >> user_status.txt
}
```

## Loop Over a List of Computer Names and Find Shared Drives

```powershell
$list = cat .\domain_computers.txt

foreach ($item in $list) {if (Test-Connection -ComputerName $item -Count 1 -Quiet) {new view \\$item /all >> share_drives.txt}}
```
