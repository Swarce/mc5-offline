# Phase 0: back up the game before the shutdown

Modern Combat 5 for Android, `com.gameloft.android.ANMP.GloftM5HM`, version **6.0.12a** (versionCode **601213**).
The patcher works on the player's own files, so every player needs this backup; nothing here is ever uploaded to a
public place (this repository is public).

## What the game is made of

| Piece | Where it lives on the phone | Can be copied without root? | Why it matters |
|---|---|---|---|
| APK splits: `base.apk`, `split_config.arm64_v8a.apk` (and `split_config.armeabi_v7a.apk` on 32-bit phones), `split_config.<density>.apk` | `/data/app/...` | Yes (any split-APK exporter, or `adb shell pm path` + `adb pull`) | Code, the native engine `libMC5.so`, ~11 MB of assets |
| **Play Asset Delivery packs** `assetPack_HighSlow0` … `assetPack_HighSlow4` | `/data/data/<pkg>/files/assetpacks/<pack>/...` (internal storage) | **No.** Download them from Play instead (below) | The game data (`data_HighSlow`, or `data_HighSlow#tcf_astc` on ASTC devices). Without them the game cannot start |
| OBB | `Android/obb/<pkg>/` | Yes | Probably empty in 6.0.12a (the installer still knows the path); copy it anyway |
| Runtime downloads ("BALD" DLC: `dlc.dat`, `dlc_mnd.dat`, `bald_*` files, `qaTestingConfigs.txt` if any) | `Android/data/<pkg>/files/` | Yes, with a PC (`adb pull`) | DLC the game downloads at runtime from Gameloft's servers |
| Local save and settings (`settings.dat`, `ur.dat`, `hc.dat`, ...) | `/data/data/<pkg>/files/` (internal) | No | The local copy of progression. Still being analysed: how much of the campaign is local and how much is in Gameloft's cloud |

Evidence: `MainActivity.java:1069-1073` (pack names), `AndroidUtils.RetrieveAssetPacksPath0..4` (pack paths read by the
native engine), `AssetsManagerPlugin.java` (Play Core `AssetPackManager`; the game asks Play to fetch the packs and never
copies them elsewhere), `SUtils.getSaveFolder()` = `getFilesDir()`, `AndroidUtils.RetrieveDataPath()` =
`Android/data/<pkg>/files`.

A re-signed (patched) APK cannot be installed over the Play version, and uninstalling the Play version deletes the
asset packs and the local save. **Do every step below while the Play version is still installed and still listed.**

## Checklist

1. **Asset packs (the most important step).** Download the five packs from Google Play with your own account, for
   example with [gplaydl](https://github.com/rehmatworks/gplaydl) on a PC:
   ```sh
   pip install gplaydl
   gplaydl link                      # pairs your Google account once
   gplaydl download com.gameloft.android.ANMP.GloftM5HM -a arm64 -o mc5-play
   gplaydl download com.gameloft.android.ANMP.GloftM5HM -a armv7 -o mc5-play-armv7   # 32-bit splits, optional
   ```
   **Tested 2026-10-26:** gplaydl 4.2.1 fetches the base and config splits (byte-identical to the Play install) but
   **not** these packs, because they are fast-follow/on-demand packs. Play serves those through a separate request,
   `POST https://play-fe.googleapis.com/fdfe/assetModuleDelivery` (the request microG's Play Store replacement
   sends), which returns each pack's slices (`assetPack_HighSlowN` plus `assetPack_HighSlowN.config.astc` on ASTC
   devices) as SHA-256-checked gzip chunks. With gplaydl's linked account that request worked: 1.15 GB download,
   1.45 GB unpacked, all ten slices verified. A small tool for this is planned (`tools/play-assets`).
2. **APK splits.** Already provided (`base.apk`, `split_config.arm64_v8a.apk`, `split_config.xxhdpi.apk`). Keep the
   gplaydl copies too.
3. **OBB folder**: `adb pull /sdcard/Android/obb/com.gameloft.android.ANMP.GloftM5HM/ mc5-obb/`
4. **Downloaded data**: play until the game has finished every download (main menu reached, a campaign mission and a
   multiplayer map loaded once), then
   `adb pull /sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/ mc5-data/`
   (Android 13+ file managers cannot open `Android/data`; use a PC.)
5. **Account**: link the game to a Gameloft or Google account in its settings so the cloud copy of the profile is
   up to date. Note your level and a few unlocks so we can check the import later.
6. **Keep the files private.** Share them with this project through a private channel (a private repository, a
   private release, or a cloud drive link). Do not attach them to a release of this public repository.

## After the shutdown

A fresh install works only from these files: the patcher takes the APK splits, and the offline build reads the asset
packs and the `Android/data` files from local storage instead of Google Play and Gameloft's servers. If the game turns
out to download more data at runtime from a Gameloft CDN, a mirror tool (`tools/cdn-mirror`, as in MCVS Offline) will be
added; that is being analysed in `docs/research/00-recon.md`.
