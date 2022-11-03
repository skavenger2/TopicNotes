# Finding XSS

<https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>  

---

## Blocked tags

If tags are blocked, copy all tags from the Portswigger cheat sheet.  
Send target request to intruder and place payload markers inside angle brackets: `<$$>`  
Paste tags into payloads and start the attack.  
Look for accepted tags.  

## Finding actions

Copy all events from the Portswigger cheat sheet.  
In the request in intruder set the payload markers inside the accepted tag, eg: `<body%20$$=1>`  
Paste the events into payloads and start the attack.  
Look for accepted events.  
