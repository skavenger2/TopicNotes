
# List of resources to get started

## Frida 1 - Known to work

<https://frida.re/docs/android/>  
<https://dl.packetstormsecurity.net/papers/general/rootdetection-bypass.pdf>  

1. Install objection
    - sudo pip3 install objection (<https://github.com/sensepost/objection>)
        - Make sure the app is open on the device, otherwise objection won't work
2. Install frida-push  
`sudo pip3 install frida-push`  
3. Download the latest frida-server for Android from the [releases page](https://github.com/frida/frida/releases) and uncompress it.  
`unxz <frida-server.xz>`  
4. Move it to the android device  
`adb push frida-server /data/local/tmp/`  
`adb shell "chmod 755 /data/local/tmp/frida-server"`  
`adb shell "/data/local/tmp/frida-server &"`  
6. Run following commands to find the package name and connect the application to objection and explore the app  
`Frida-ps -Ua`  
`objection --gadget package_name explore`  
OR  
`adb shell ps | grep <app name>`  
`objection --gadget package_name explore`  
5. Run the following command to disable root  
`android root disable`  

## Frida 2

<https://redfoxsec.com/blog/android-root-detection-bypass-using-frida/>  

Need:  
- Rooted device/emulator
- Platform-tools
- Frida packages for Python
- Target app

1. List processes with Frida  
`frida-ps -Uai`  
2. Inject [this](https://codeshare.frida.re/@dzonerzy/fridantiroot/) antiroot script into the process  
`adb push <path_to_fridantiroot.js> /data/local/tmp`  
3. Run the following command on the device to start the frida-server  
`adb shell /data/local/tmp/frida-server &`   
4. Inject fridantiroot.js script into the target application  
`frida -U -f <your_application_package_name> -l <path_to_fridantiroot.js_on_your_computer> --no-paus`  
5. Open the application

## Xposed

1. Install Xposed:  
<https://repo.xposed.info/module/de.robv.android.xposed.installer>  
2. Install "RootCloak" (Xposed module)
3. Open RootCloak > Add/Remove Apps > Tap target app
4. Open target app to check if it worked

## Manual with APKTool

1. Decompile APK with apktool  
`apktool d target.apk -o output/dir`  
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
`apktool b modified.apk -o output/dir`  
5. Sign with jarsigner tool  
`path/to/my-key.keystore -storepass password -keypass password target-new.apk alias_name`  
- May need to generate the keystore first with keytool  
`keytool -keygen -v -keystore my-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity10000`  
6. Install the new version

