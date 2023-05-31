# ADB Cheatsheet

## Packages

List installed packages:  

```bash
pm list packages
```

List a package's path:  

```bash
pm path <full-package-name>
```

## Activities

List activities in an package:  

```bash
dumpsys package | grep -i '<part-of-package-name>' | grep Activity
```

Start an activity:  

```bash
am start -n yourpackagename/.activityname
```
