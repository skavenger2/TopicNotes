# WordPress

## WordPress Version

Look for `<meta name="generator" content="WordPress 3.5.2" />` in the HTML source.  

## Enumerate Plugins

Find `wp-plugins.txt` in the same folder as this file.  

```bash
ffuf -u https://target.com/wp-content/plugins/FUZZ -w ./wp-plugins.txt
```

## User Enumeration

Fuzz this endpoint: `http://target.com/?author=1`  
