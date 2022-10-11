# Add Certificate to Burpsuite to Proxy Traffic


```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem <hash>.0
./emulator -avd <device name> -writable-system
adb root
adb remount
adb push 9a5ba575.0 /sdcard/Download
adb shell
cp /sdcard/Download/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0
reboot
```
