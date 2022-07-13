
# Jailbreak Bypasses

Package managers:  
Cydia: <https://www.cydiafree.com/>  
Sileo: <https://getsileo.app/>  

## Bypass with tweaks

Various tweaks to bypass jailbreak checks.  
<https://ios.cfw.guide/blocking-jailbreak-detection/> covers some of the tools listed below.  

| Tweak | Repo |
| --- | --- |
| Hestia | <https://repo.hackyouriphone.org/> |
| A-Bypass | <https://repo.co.kr/> or <https://repo.rpgfarm.com/> |
| Liberty Lite | <https://repo.hackyouriphone.org/> |
| iHide | <https://repo.kc57.com> |
| Choicy | <https://www.ios-repo-updates.com/repository/opa334-s-repo/> |
| KernBypass | <https://repo.hackyouriphone.org/> |
| VNodeBypass| <https://cydia.ichitaso.com> |
| Shadow | <https://ios.jjolano.me/> |
| FlyJB X | <https://repo.hackyouriphone.org/> |
| UnSub | <https://repo.hackyouriphone.org/> |

For any of the above, add the repo to Cydia or Sileo:  

- Open Cydia or Sileo
- Tap on Sources
- Tap "Edit", "Add" or "+"
- Enter the repo
- Tap "Add Sources" and "Add Anyway" or "I accept the risks, continue" and "Continue"
- Most add a new menu in the settings app. You can then select which apps it should apply for

---

Additional list of tweaks:  

- Choicy – Can disable tweak injection for each app separately while leaving it on for the rest. Pretty useful and popular, also Free. (REPO: Choicy)
- KernBypass Unofficial – Attempts to bypass jailbreak detection at the kernel level. Pretty popular but may not work on all apps.
- VnodeBypass – Popular solution, but may not work for all applications.
- A-Bypass  – Works for some apps including some smaller banking apps (REPO: <https://repo.co.kr/>).
- Liberty Lite – Works well on small banking apps, but may fail on more popular/beefy apps. (REPO: <https://ryleyangus.com/repo/>).
- PicaHide – A good Snapchat Jailbreak Detection Bypass. Still, do know that a small failure and you CAN get banned by Snapchat. (REPO: <http://apt.thebigboss.org/repofiles/cydia/>).
- KernBypass Original – Compatible with CheckRa1n and OdysseyRa1n, may or may not work for your particular app. (Source: GitHub).
- Jailprotect – Works on iOS 10 and disables Tweak Injection. I’d use Choicy nowadays, but do know this exists too. (REPO: <https://julioverne.github.io/>).
- Shadow – Works on simple apps. More complicated banking apps cannot be bypassed with this. It was tested on Unc0ver. (Source: GitHub).
- FlyJB X – Used to work relatively well and may still work on iOS 14 if you can find a reliable and safe DEB. The developer left the community and removed their repo.
- TsProtector 8+ – This one works best on iOS 8.x devices. It may work on iOS 9 but I did not test it. (REPO: <https://typ0s2d10.appspot.com/repo/>).
- AJB – It’s older and may or may not work. I have a hard time even finding it nowadays.
- Hestia – Works on iOS 11.0 – iOS 14 and it’s free, but may or may not work for you.
- De-Bypass – Supports Fire Emblem Heroes, Seikimatsu Days, Uta Macross, ONE PIECE: Thousand storm.
- xCon – Works for some apps, may not work for others, check the xCon compatibility table here.
- Tweaks Manager – Like Choicy, disables tweak injection. Not always enough.

You will likely need a combination of these to have any success with most of your apps. Very popular combinations include Choicy + KernBypass or Choicy + VnodeBypass.  

## Bypass manually

<https://www.appknox.com/blog/ios-jailbreak-detection-bypass>  Has some different methods to bypass jailbreak detections with "frida" and "objection"  

Via hooking:

1. Install Frida Server
    - Open Cydia
    - Sources > Edit
    - Add > <https://build.frida.re>
    - Search > frida > Install
2. Install objection
    - sudo pip3 install objection (<https://github.com/sensepost/objection>)
        - Make sure the app is open on the device, otherwise objection won't work
3. Connect device via USB and trust the device
4. Run following commands to find the package name and connect the application to objection and explore the app  
`Frida-ps -Ua`  
`objection --gadget package_name explore`  
5. Run the following command to search for a specific class  
`ios hooking search classes jailbreak`  
6. Run the following command to watch methods available for the given class  
`ios hooking watch class JailBreakDetection` - change "JailBreakDetection" to the applicable class  
7. Run the following command to dump the value of the given method  
`ios hooking watch method "+[JailBreakDetection isJailbroken]" --dump return` - the "+" is based on what was shown when watching classes (could be "+" or "-") - JailBreakDetection is the name of the class, isJailbroken is the method of the class  
8. Run the following command to set the return value of the given method  
`ios hooking set return_valued "+[JailBreakDetection isJailbroken]" 1`

Via Objection:  

1. Install Frida Server
    - Open Cydia
    - Sources > Edit
    - Add > <https://build.frida.re>
    - Search > frida > Install
2. Install objection
    - sudo pip3 install objection (<https://github.com/sensepost/objection>)
        - Make sure the app is open on the device, otherwise objection won't work
3. Connect device via USB and trust the device
4. Run following commands to find the package name and connect the application to objection and explore the app  
`Frida-ps -Ua`  
`objection --gadget package_name explore`  
5. Run the following command to bypass the jailbreak detection  
`ios jailbreak disable`  

Via Frida:  

1. frida -U -f package_name -l jailbreak.js --no-pause
    - <https://codeshare.frida.re/@liangxiaoyi1024/ios-jailbreak-detection-bypass/> (Download the script from codeshare according to your iOS version)
