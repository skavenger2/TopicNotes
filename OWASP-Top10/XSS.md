# XSS Notes
<https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>  

## Finding XSS

### Blocked tags

If tags are blocked, copy all tags from the Portswigger cheat sheet.  
Send target request to intruder and place payload markers inside angle brackets: `<$$>`  
Paste tags into payloads and start the attack.  
Look for accepted tags.  

### Finding actions

Copy all events from the Portswigger cheat sheet.  
In the request in intruder set the payload markers inside the accepted tag, eg: `<body%20$$=1>`  
Paste the events into payloads and start the attack.  
Look for accepted events.  

---

## Submit Forms to Bypass CSRF

Inject malicious code that executes when the page is loaded.  
If the form you want to submit is the first on the page, `document.forms[x]` will be zero (0)  

```javascript
<body onload="document.forms[0].submit()">
```
