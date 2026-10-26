# The patcher

`patcher/` turns the player's **own** MC5 6.0.12a split set into an offline-ready,
re-signed split set that loads `libmc5offline.so` before the game. It never ships
or contains any Gameloft file: every input is the player's, every output is signed
with the player's own key.

Target build: `com.gameloft.android.ANMP.GloftM5HM`, versionCode **601213**
(6.0.12a). The patcher refuses any other base unless `--force` is given.

## What it does

1. **Fingerprints the base.** Reads `package`/`versionCode` with `aapt2` and
   refuses on mismatch (`--force` overrides, with a warning). Locates
   `FrameworkApplication` in the dex and the earliest lifecycle method it defines.
2. **One surgical dex edit** (via dexlib2, structural — never raw bytes). In the
   dex that holds `FrameworkApplication` (classes4.dex in this build) it:
   * adds a tiny class `com.gameloft.android.ANMP.GloftM5HM.MC5Offline` with
     `static void boot() { System.loadLibrary("mc5offline"); }`, and
   * prepends a zero-register `invoke-static {}, MC5Offline->boot()V` as the very
     first instruction of `FrameworkApplication.attachBaseContext`.

   `attachBaseContext` is the earliest `Application` callback, so our library
   loads before any game code (and so before `libMC5.so`). Zero registers means
   no register reallocation in the host method — the smallest possible edit, and
   verifier-safe. The edit is idempotent (it is skipped if a boot call is already
   present).
3. **Adds `libmc5offline.so`** to each ABI config split at `lib/<abi>/`, stored
   uncompressed. The app declares `android:extractNativeLibs="false"`, so every
   `.so` must be uncompressed and 4096-page-aligned — `zipalign -p` does that, the
   same as the game's own libraries.
4. **Re-signs every APK** in the set — base, ABI split(s), density/language
   splits and asset packs — with one key, after stripping Gameloft's old v1
   signature. Signs v2+v3 (minSdk 24), then `apksigner verify`s each. All splits
   in an `install-multiple` session must share one certificate; this guarantees it.
5. **Emits `install-set.sh`** — one `adb install-multiple -r` of the whole set.

Nothing is written in `--dry-run`: it prints the fingerprint and the full plan
and stops.

## The signing key = the save

Android treats a reinstall as an *update* (and keeps app data) only when the new
APKs carry the same signing certificate. **Reuse the same keystore for every
build.** `--gen-key` creates a long-lived key the first time; keep that file.
Lose it and a future rebuild can only be installed fresh, losing the local save.

## Asset packs (offline)

The game's textures ship as on-demand/fast-follow **asset packs** (per module a
tiny base slice + a large `.config.astc` slice). Normally Play delivers them at
runtime; offline we install them as splits in the same `install-multiple` session
so they are present on disk and the in-process asset-pack shim reports them as
installed. Pass each pack APK with `--pack`; they are re-signed only.

## Usage

```sh
# Inspect / fingerprint only:
java -jar patcher/build/libs/mc5-patcher.jar info \
  --base base.apk --build-tools "$ANDROID_HOME/build-tools/34.0.0"

# Patch (one abi + its lib, the density split, every asset pack):
java -jar patcher/build/libs/mc5-patcher.jar patch \
  --base       com.gameloft.android.ANMP.GloftM5HM-601213.apk \
  --abi-split  arm64-v8a=...-config.arm64_v8a.apk \
  --lib        arm64-v8a=artifacts/lib/arm64-v8a/libmc5offline.so \
  --abi-split  armeabi-v7a=...-config.armeabi_v7a.apk \
  --lib        armeabi-v7a=artifacts/lib/armeabi-v7a/libmc5offline.so \
  --split      ...-config.xxhdpi.apk \
  --pack       assetPack_HighSlow0.apk --pack assetPack_HighSlow0.config.astc.apk \
  ... (all packs) ... \
  --gen-key --ks mc5-offline.keystore \
  --out out/ --build-tools "$ANDROID_HOME/build-tools/34.0.0"

bash out/install-set.sh      # uninstall any Play-Store copy first
```

`--build-tools` may be omitted if `$MC5_BUILD_TOOLS` is set. Keep every ABI you
have — pass an `--abi-split`/`--lib` pair per ABI.

## Build the patcher

```sh
cd patcher && gradle jar      # -> patcher/build/libs/mc5-patcher.jar
```

Dependencies (resolved from Maven Central): `org.smali:dexlib2:2.5.2` and guava.
External tools used at runtime come from the Android SDK build-tools (`aapt2`,
`zipalign`, `apksigner`) and the JDK (`keytool`).

## Verified so far (host, no device yet)

On the real 601213 base + arm64 split + xxhdpi split + an asset pack:

* base fingerprint matches; `FrameworkApplication.attachBaseContext` in classes4.dex;
* patched `classes4.dex` disassembles to the injected `invoke-static …MC5Offline->boot()`
  as instruction 0, and `boot()` = `const-string "mc5offline"` → `System.loadLibrary`;
* `libmc5offline.so` present in the arm64 split, STORED, page-aligned (`zipalign -c -p`);
* all outputs share one signer certificate; `apksigner verify` passes; whole-archive
  `zipalign -c` passes (resources.arsc and dex 4-aligned).

Not yet installed on a device — that is the end-of-M0 test.
