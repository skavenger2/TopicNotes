# Frida

Frida-server link [here](https://github.com/frida/frida/releases)  
Decompress with `unxz`  

## Frida-ps

```bash
# List processes
frida-ps -U

# List running apps
frida-ps -Ua

# List installed apps
frida-ps -Uai

# Connect frida to specific device
frida-ps -D <device-id>
```

## Example login bypass with python

Using [Sieve APK](https://github.com/as0ler/Android-Examples/blob/master/sieve.apk)  

```python3
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
    //Obtain referrence of the Activity currently running
    var MainActivity = Java.use('com.mwr.example.sieve.MainLoginActivity');
	//Obtain reference of the function whcih needs to be called
    MainActivity.checkKeyResult.implementation = function (b) {
        send('checkKeyResult');
	//Calling the function and passing the boolean parameter as true
        this.checkKeyResult(true);
		
        console.log('Done:');
    };
});
"""

process = frida.get_usb_device().attach('com.mwr.example.sieve')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

## Log function and method invocations  

`-m` flag specifies Objective-C methods  
Use wildcards to match on simple patterns  

Example: NSURLRequest -initWithURL:cachePolicy:timeoutInterval:  
`frida-trace -U -m "-[NSURLRequest initWithURL:cache*]" myApp`  

## Modifying handlers:  

Frida's javascript API can be used  
`ObjC.Object()` creates a JavaScript binding to the object specified by an argument  
`ObjC.Object(ards[2]).toString()` can be used to convert hex to ASCII for example  

## Ways to use frida:  

- monitor method I/O at runtime
- analyze app-specific data
- bypass controls
- manipulate app behaviour
- explore an app under the hood

## Tracing functions on Android  

frida can trace single functions or libraries  
`-i` flag will apply a pattern to find functions  
`-I` flag will hook all functions under the specified library  
`frida-trace -U -i open* -I *sqlite* com.google.android.apps.photos`  

## Using a trace to explore  

Example: iOS keychain  
use `-f` to launch the app  
`frida-trace -U -m "*[*eychain* *]" -i SecItemCopyMatching -f [target]`  

## Directly call methods with Frida CLI  

JavaScript REPL (read-Execute-Print-Loop)  
Load "agent" scripts  

Example DVIA:  

```bash
frida -U DVIA   # open the application
bindings = ObjC.classes.PDKeychainBindings.SharedKeychainBindings()
controller = ObjC.classes.PDKeychainBindingsController.SharedKeychainBindingsController()
controller.$ownMethods   # show methods contained in "controller"
bindings.$ownMethods  # show methods contained in "bindings"
controller.values()   # dump values in handle form
controller.values().toString  # dump values as string
controller.stringForKey_("keychainValue").toString()  # confirm stored secret
```

## Automate with Agent scripts  

Once tested, bundle it into an agent  
- self-contained JavaScript file
- injected into the target
- functions you define can be called from the CLI

`frida -l agent.js [target]`  

## Tracing Java methods on Android  

no support yet for matching Java methods in frida-trace  
replace the method implementation  
use the Java API on Android
- Java.perform
- Java.use

Building agent.js  
```javascript
'use strict'

if (Java.available) {
  Java.perform( function() {
    const WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = funtion(url) {
      console.log("\x1b[2m[*] WebView loadUrl -> \x1b[0m\x1b[34;1m" +url + "\1b[0m");
      this.loadUrl.overload("java.lang.String").call(this, url);
    };
  });
}
```

How can we use agents  
- automate tedious tasks
- define new commands for the cli

BlueCrawl collects metadata from a device
- leverages CLI for easy script injection
