# Ship Me

**Flag:** `TFCCTF{parcelables_are_safer_not_safe}`

# Ship Me — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
ANDROID — 335 pts — static — ~28 solves.
- Brief: 'They can throw away your package! Be careful'. Your app is installed with 'adb install -g path'; the flag is shipped via 'am start -n me.ship/.MainActivity --eu package ...'.
- Required skills: JDK + Android build tools (aapt2/d8/apksigner/android.jar) — INSTALLED (javac, aapt2, d8 via /opt/r8.jar, apksigner, zipalign, android.jar API23); adb not needed locally (remote installs it).
- First hypotheses: build an APK with a MainActivity that reads the 'package' extra and exfiltrates (start a controlled activity, write to a world-readable file, or POST to a listener); 'package' extra likely contains the flag directly.

## Discovery & ideation (2026-09-05)
FILES: shipme-release.apk (2.1MB, Android release). Desc: our app installed via 'adb install -g path'; flag shipped via 'am start -n me.ship/.MainActivity --eu package <...>'. 'They can throw away your package! Be careful.'
HYPOTHESES (ranked):
1. Our submitted APK must declare package 'me.ship' with activity '.MainActivity'; when the harness runs 'am start -n me.ship/.MainActivity --eu package <flag>', MainActivity reads the 'package' string extra and exfiltrates (Log.i -> logcat, POST to a listener, write to /sdcard, or start another activity). Build it with the local Android toolchain.
2. Reverse the provided shipme-release.apk to confirm exact package/activity names + how the 'package' extra is passed (maybe it's a parcelable/JSON, not a plain string) and whether MainActivity must call back in a specific way.
3. 'They can throw away your package' may hint the flag is passed as a Parcelable ('package' of type Parcelable?) - handle getParcelableExtra vs getStringExtra.
NEXT: decompile the APK (aapt dump badging / jadx) to confirm package + MainActivity contract, then build + submit the solver APK.


## Reverse + build + first submit (2026-09-05 ~16:45 UTC)
FINDINGS:
- Reversed shipme-release.apk (jadx). Package me.ship, activity me.ship.MainActivity (exported, MAIN/LAUNCHER). No providers/services/receivers. minSdk 33, target 36.
- MainActivity reads extra "package" as Uri via intent.getParcelableExtra("package", Uri.class); parses shipme://cargo/?name=FLAG&origin=challenge; name=flag. Then intent.removeExtra("package") ("throw away your package").
- Platform android.koth.pro: login via X-Auth = team invite token b899...7063. /provision (challenge="ShipMe", file=apk). Logs only capture tag "TFCCTF" (Log.i("TFCCTF", ...)).
- Built solver APK (package me.ship, MainActivity reads Uri extra + logs TFCCTF). Signed v1+v2+v3 (debug keystore).
- First submit: session ts640kdkz3 -> "[error] Run failed" right after "Installing submitted APK". Install failed.
HYPOTHESES:
- H3: challenge APK (shipme.apk, same package me.ship, different cert) is pre-installed during "Preparing challenge"; our me.ship APK install fails with UPDATE_INCOMPATIBLE. => need different package + exploit.
- H4: our APK has a technical install problem (build toolchain).
NEXT: probe submit with different package (com.probe.ship) to distinguish H3 vs H4.


## Breakthrough (2026-09-05 ~19:40 UTC)
- The harness GRANTS WRITE_SECURE_SETTINGS to the solve APK (SELF_ENABLE_OK). Our app can self-enable its own AccessibilityService via Settings.Secure.putString(ENABLED_ACCESSIBILITY_SERVICES).
- Accessibility service connected (A11Y_CONNECTED) and read the active window tree.
- First attempt had a dex bug: anonymous inner class MainActivity$1 not included in D8 (NoClassDefFoundError). Fixed by passing all .class files to D8; service now dumps all windows + active window periodically (400ms) and searches for TFCCTF{...}.
- Plan: resubmit fixed self-a11y solver -> service reads target me.ship UI (flag TextView) despite FLAG_SECURE -> Log.i("TFCCTF","FLAG=...").
