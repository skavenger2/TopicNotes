
# List of resources to get started

Root Android Studio AVD with SuperSU  
<https://github.com/0xFireball/root_avd>  

## Frida 1

<https://frida.re/docs/android/>  
<https://dl.packetstormsecurity.net/papers/general/rootdetection-bypass.pdf>  

1. Install objection (<https://github.com/sensepost/objection>)  
```bash
sudo pip3 install objection
```  
2. Install frida-push  
```bash
sudo pip3 install frida-push
```  
3. Attempt to open the target app on the device to ensure the process is running  
4. Download the latest frida-server for Android from the [releases page](https://github.com/frida/frida/releases) and uncompress it.  
```bash
unxz <frida-server.xz>
```  
5. Move it to the android device  
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```  
6. Run following commands to find the package name and connect the application to objection and explore the app  
```bash
Frida-ps -Ua  
objection --gadget package_name explore  
# OR  
adb shell ps | grep <app name>
objection --gadget package_name explore  
```
6. Run the following command to disable root  
```bash
android root disable
```

## Frida 2

<https://redfoxsec.com/blog/android-root-detection-bypass-using-frida/>  

Need:  
- Rooted device/emulator
- Platform-tools
- Frida packages for Python  
```bash
sudo pip3 install frida-push
```
- Target app

1. Attempt to open the app (required so that the process is running)
2. Download the latest frida-server for Android from the frida [releases page](https://github.com/frida/frida/releases) and uncompress it.  
```bash
unxz <frida-server.xz>
```  
3. Move frida-server to the android device  
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```
4. Copy [this](https://codeshare.frida.re/@dzonerzy/fridantiroot/) antiroot script to a file on your local system  
- [Alternate fridantiroot](https://gist.github.com/pich4ya/0b2a8592d3c8d5df9c34b8d185d2ea35)  
5. List processes with Frida  
```bash
frida-ps -Uai
```  
6. Inject fridantiroot.js script into the target application  
```bash
frida -U -f <your_application_package_name> -l <path_to_fridantiroot.js> --no-paus
```  
7. Open the application

## Patching Smali

Reference: <https://medium.com/swlh/defeating-android-root-detection-with-smali-patching-46c082c27a81>  

---

Decompile the APK file with APKTool  

```bash
apktool d <application.apk>
```  

Open this source code in a text editor  

Search for any of the following strings:  

- test-keys
- su
- Superuser.apk
- eu.chainfire.supersu
- com.noshufou.android.su
- com.thirdparty.superuser
- com.koushikdutta.superuser
- com.zachspong.temprootremovejb
- com.ramdroid.appquarantine
- stericson.busybox
- Superuser
- SuperSU

Most likely, these are all in the one method of smali code.  
Find the start of this method, for example:  

```smali
.method public static a(Landroid/app/Activity;)V
```  

Take note of the trailing character and find out what it wants. In this case, "V", return void.  
To bypass the root check, find the first line of code in this method and add some just before it.  
For example, this code:  

```smali
.method public static a(Landroid/app/Activity;)V
    .locals 9

    .prologue
    const/4 v1, 0x1

    const/4 v0, 0x0

    .line 57
    .line 1072
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v4
    
    # Root checks continue...
```

Becomes:  

```smali
.method public static a(Landroid/app/Activity;)V
    .locals 9

    .prologue
    const/4 v1, 0x1

    const/4 v0, 0x0

    .line 57
    .line 1072
    return-void

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v4
```

*Note the added "return-void" after ".line 1072"*  
This bypasses all string checks by returning before they occur.  

Recompile the APK. The VSCode extension "APKLab" is very useful.  
Install the recompiled APK on the android device, it should now run.  

## Xposed

1. Install Xposed:  
<https://repo.xposed.info/module/de.robv.android.xposed.installer>  
2. Install "RootCloak" (Xposed module)
3. Open RootCloak > Add/Remove Apps > Tap target app
4. Open target app to check if it worked

## Manual with APKTool

1. Decompile APK with apktool  
```bash
apktool d target.apk -o output/dir
```  
2. Most root detection techniques rely on checking for files on the OS that indicate the device has been rooted. Using GREP, search for any of the follow strings and change them to something random:
- Superuser
- Supersu
- /su
- /system/app/Superuser.apk
- /system/bin
- /system/bin/su
- /system/sd/xbin
- /system/xbin/su
- /system/xbin
- /data/local
- /data/local/bin
- /data/local/xbin
- /sbin
- /system/bin/failsafe
- /vendor/bin
3. Note: Other detection techniques look for any of the below-installed packages on the mobile device at runtime:
- supersu.apk
- Busybox
- Root Cloak
- Xpose framework
- Cydia
- Substrate
4. Build new version of the apk with apktool  
```bash
apktool b modified.apk -o output/dir
```  
5. Sign with jarsigner tool  
```bash
path/to/my-key.keystore -storepass password -keypass password target-new.apk alias_name
```  
- May need to generate the keystore first with keytool  
```bash
keytool -keygen -v -keystore my-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity10000
```  
6. Install the new version

## Other

Magisk  

## Mitigations
<https://www.indusface.com/learning/how-to-implement-root-detection-in-android-applications/>  

---

Implement emulator detection  

- Having emulator detection gives one layer of additional projection to your application against runtime manipulation.

Implement root detection checks  

- With the invention of RootCloak, RootCloak Plus, “system-less” root, Magisk Hide, Frida root bypass scripts, bypassing root detection checks has become easier. Hence, there is no single check that detects all types of rooting methods. Hence, implementing multiple checks will ensure a higher detection rate.

Implement Frida detection

- Mobile application penetration testers commonly use Frida for root detection bypass and SSL pinning bypass. Hence, it’s crucial to implement Frida hooking detection to prevent Frida from hooking into your application.

Implement Magisk detection

- When a device is rooted via “systemless root” method, modifications are stored in the boot partition. Due to this, basic root detection checks are bypassed easily. Magisk is a way to root an Android device “systemlesss” way. Via Magisk Manager app, modules and other features can be configured.
- Magisk Manager can be hidden by changing its package name to a random name. Another notable feature Magisk Hide prevents applications from detecting the presence of roots. Hence, it’s crucial to implement Magisk detection to prevent the Android app from running on a rooted device.

Code obfuscation

- Application reverse engineering is a common technique used by application penetration tester to understand an application’s technical details. Analyzing application source code helps them gain a deeper understanding of the application. There are some techniques and open-source projects to obfuscate some parts of the code.
