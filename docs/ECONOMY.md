# MC5 Offline: save, currencies and unlock codes

This doc covers how MC5 Offline keeps your progress, what the two currencies are, and how the MCVS-style unlock codes
work. The research behind it is in [research/04-progression.md](research/04-progression.md).

## 1. Where your progress lives

Modern Combat 5 6.0.12a keeps **no save on the phone**. The app constructor marks the game as online
(`0x4e2510`), so the client uploads small updates to the server: mission start and end, loadouts, skills, the age
gate answer, tutorial flags and difficulty. At every login it expects the whole player document back as
`TCP_Profile`. The offline server now keeps that document on the phone and sends it back at login. Before this, every
launch was a fresh account.

The files are in the app's external files folder (the same folder as `mc5offline.log`):

```
/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/MC5Offline/
  settings.json   your settings (created with defaults on first launch; edit it to change behaviour)
  profile.json    your player document (XP, currencies, unlocks, campaign progress, statistics)
  state.json      server bookkeeping: redeemed codes, loadouts, mission de-duplication, crash guards
  *.bak           the previous good copy of each file
  items.json      optional: item lists for the unlock codes (see §3.3)
```

* Writes are atomic. Each save writes a temporary file, fsyncs it, keeps the old file as `.bak`, then renames.
* A file that does not parse is moved aside to `<name>.broken-<time>`. It is never overwritten silently, and the
  `.bak` copy is loaded instead.
* The folder survives app updates. It is removed when the app is uninstalled, so back it up with
  `adb pull /sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/MC5Offline`.
* If the external folder is not writable, the internal one (`/data/data/<package>/files/MC5Offline`) is used instead.

What is kept between launches:

| Kept | From |
|---|---|
| Age, gender, birth year, call sign (the age gate is not asked again) | 0x59, 0x0b |
| XP and skill points earned in missions | 0x11 (mission end) |
| Campaign progress per mission node, plus objectives 2 and 3 | 0x10 (start) + 0x11 (end) |
| Loadouts and the selected loadout | 0x16 |
| Mission statistics (kills, time played, …) | 0x11, 0xac |
| Menu-tutorial flags and difficulty | 0x32, 0xa3 |
| Currencies and unlocked items | server-owned (codes; §2, §3) |

Not kept yet (the client sends them, and the server records them in `state.json` for later):

* **Bought skills.** The skill frame (0x17) carries no cost, and the profile needs the skill names.
  * After a restart your skills reset and their skill points come back, so nothing is lost.
* **Achievements, and the skill points they award.** The profile format needs achievement names, and the
  reward amounts come from a table that is not dumped yet. The game unlocks a mission's achievements and credits
  their skill points locally, but does not report the amount. After a restart, those skill points are missing from
  the save.

**First launch on this build:** the server has no save yet, so the game runs its first-run flow once more (age gate,
tutorial). Every launch after that loads your save.

## 2. Currencies

| In game | Inventory item | Notes |
|---|---|---|
| **Credits** (soft, green) | `diamond_dust` | |
| **Gold** (hard) | `credits` | yes, the hard currency's item is called "credits" |

* The `-1` you saw on the top bar is not a game value. It is the top bar's placeholder before the native side has
  sent anything.
* An absent item counts as 0. A profile that carries both items (any value, including 0) should show real numbers.
* `economy.startCredits` / `economy.startGold` set the amounts a new save starts with.
* The `UNLOCKCURRENCY` code adds a large amount (§3).

## 3. Unlock codes (MCVS style)

**Where:** Main menu → Settings → the **Redeem** button in the bottom row. MC5 has its own redeem screen. The code
goes to the server over the game's TS channel (frame 0x53), and the server answers on the same channel. Nothing goes
over the internet.

### 3.1 Codes

| Code | Grants |
|---|---|
| `UNLOCKALL` | every class, weapon, attachment, camo, gear item and kill signature |
| `UNLOCKCLASSES` | all 11 soldier classes (assault, heavy, recon, sniper, support, mercenary, sapper, morph, paladin, enforcer, tracker) |
| `UNLOCKWEAPONS` | the classes, then every weapon |
| `UNLOCKATTACHMENTS` | the weapons, then every weapon attachment |
| `UNLOCKCAMOS` | every camo |
| `UNLOCKGEAR` | body pieces, body camos, masks, trinkets |
| `UNLOCKKILLSIGS` | every kill signature that has an unlock condition |
| `UNLOCKCURRENCY` | +1,000,000 Credits and +100,000 Gold (both capped at 2,000,000,000) |
| your own | see `redeem.codes` below |

**Command codes** can be used any number of times and show no reward popup:

| Code | Effect |
|---|---|
| `UNLOCKZONES` | opens every campaign zone |
| `GODMODE` / `INFINITEAMMO` / `INFINITEMEDKITS` | toggle the game's own debug cheats; they persist and are re-applied at each mission start |
| `CHEATSOFF` | turns all three off |
| `BOTMATCH` | **experimental:** starts a local multiplayer match with you as the host and `bots.count` bots. Open the Multiplayer menu once first |

**Campaign zones** open the way they did online. Once you have finished every story mission of a zone, the next
zone unlocks when you return to the menu. The server reads the zone and mission list from your own game data.

How the codes behave:

* Codes are case-insensitive and surrounding spaces are ignored.
* Each code works **once per save**. Add a number to use it again: `UNLOCKALL2`, `UNLOCKALL3`, …
* Items you already own are skipped.
* Prerequisites go first, as in MCVS. Classes are granted before weapons, and weapons before attachments.
* The grant is pushed to the game immediately (inventory-change frames, at most 400 items per frame) and is also
  stored in the save, so it is in place at every later launch.
  * A code entered during a mission applies at the next launch.
  * If a live push ever misses, the next launch delivers everything anyway.
* An unknown or already-used code shows the game's "invalid code" message.
* A valid code closes the redeem popup without a reward popup. The reward popup looks the item up in the game's shop
  catalog, which is empty offline, and an unknown item would crash it, so the server only sends a reward popup for
  items the catalog defines.

### 3.2 Where the item names come from

Nothing from the game is shipped. All item names are read **from your own game data** at runtime: the in-memory
armory (built from your `armory.bin`), the skill tree (classes) and the kill-signature table.

* **When:** on the game thread, the first time the game sends a loadout (right after every login) or a redeem code.
* **Checks:** the game stores each item's hash next to its name, and every list is checked against those hashes. A
  list that does not check out is left out; it is never guessed. If the class list is missing, the game's 11 class
  identifiers are used instead.
* **What is granted:** free/default items are skipped, since you already own them. Weapons get count 1 (the base
  weapon; a higher count would mean a PRO level). Attachments are only the pairs your weapons actually accept.

The name lists are also written to `MC5Offline/dumps/`, so you can inspect them.

If a list is not available yet (for example a code redeemed before the dump ran), the code is reported invalid and
**not used up**, so you can simply enter it again.

### 3.3 items.json (optional)

`MC5Offline/items.json` can supply or override the lists:

```json
{"weapons":["..."],"attachments":["<weapon>#<attachment>"],"camos":["..."],"gear":["..."],"classes":["..."]}
```

## 4. settings.json

Created with these defaults on first launch. Unknown keys are ignored. MCVS names are accepted where they exist
(`assets.couponsEnabled`, `assets.coupons`).

```json
{
 "settingsVersion":3,
 "redeem":{"enabled":true,"codes":{},"popup":"auto"},
 "unlockAll":false,
 "unlocks":{"batchSize":400,"batchDelayMs":250,"startDelaySeconds":10,"live":true},
 "economy":{"xpMultiplier":1.0,"spMultiplier":1.0,"startCredits":0,"startGold":0,
            "codeCredits":1000000,"codeGold":100000,"purchases":"none"},
 "profile":{"send":true},
 "config":{"sendGame":true},
 "bald":{"mode":"mirror","holdMs":2000,"requireSizes":true}
}
```

| Setting | Effect |
|---|---|
| `redeem.enabled` (= MCVS `assets.couponsEnabled`) | turn the codes off |
| `redeem.codes` (= MCVS `assets.coupons`) | custom codes: `{"MYCODE":{"items":{"<item>":1},"credits":5000,"gold":100}}` |
| `redeem.popup` | `"auto"`: a reward popup only for items the shop catalog defines; `"none"`: never |
| `unlockAll` | grant the `UNLOCKALL` set once per save, `startDelaySeconds` after the menu first appears (never during a mission) |
| `unlocks.batchSize` / `batchDelayMs` | how many items per push frame, and the pause between frames |
| `unlocks.live` | `false`: never push; grants apply at the next launch |
| `economy.xpMultiplier` / `spMultiplier` | scale mission XP / skill points (the mission-end reply and the save) |
| `economy.startCredits` / `startGold` | starting currencies of a new save |
| `economy.codeCredits` / `codeGold` | what `UNLOCKCURRENCY` adds |
| `profile.send` | `false`: never send the save at login (every launch is a fresh account; the save is still recorded) |
| `config.sendGame` | `false`: send the old empty game config (brings back the Profile → stats crash, unless the guard patch is on) |
| `bald.mode` | `"mirror"` (default): answer the DLC manager from **your own** restored `files/bald` folder (§6); `"off"`: always 404 (zones and MP maps stay "not downloaded") |
| `bald.holdMs` | every DLC request the server does not answer waits this long before its 404, so the game's retry loop runs about once every 2 s instead of ~40 times a second |
| `bald.requireSizes` | `true` (default): every file must have exactly the size your `bald___hashes___.txt` lists, or the mirror stays off (a truncated file would be mounted) |

The environment variable `MC5_TS_PROFILE=0` also disables the login profile.

## 5. Crash guards

Two behaviours are guarded: the login profile apply (confirmed working on device), and the DLC manager becoming
"ready" (off by default since it crashed the menu). Each guard works like this:

* Before it starts, the guard is written to `state.json` → `guards`.
* It is cleared once the game is clearly still alive: back in the menu or in a mission, or 20 s (profile) / 60 s
  (BALD) later.
* If the app dies before that on **two launches in a row**, the feature switches itself off and the log says so
  (`[guard] '<name>' AUTO-DISABLED`).
* To try again, delete that entry from `state.json`.

## 6. Campaign zones and MP maps (your own DLC backup)

The campaign zones (Downtown, Venice, Construction, Blackwater), the multiplayer maps, vehicles and the outro video
are runtime DLC that the game downloaded while it was online. They live in:

```
/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/bald/
  bald___index___.txt  bald___version___.txt  bald___toc___.txt  bald___hashes___.txt
  bald_android_astc_h_z0_mp_gla2_7   bald_android_astc_h_z3_venice_gla2_2   ...   (one file per asset)
  bald_android_astc_h_map_android_dlc_<n>
```

If you restore that folder from your backup, MC5 Offline answers the game's DLC check with **your own** index file.
The game then uses the files it already has. Nothing is downloaded, and nothing is shipped by this project.

The folder is **read-only** to MC5 Offline. The server never writes, renames or deletes anything in it. It only reads
the four `bald___*___.txt` files, the DLC map, and the file sizes. It also never sends the game a file list (toc),
because a different list would make the game delete the assets that list leaves out. **Still, keep a copy of the
folder off the phone.**

At startup the server checks the folder and logs the result (`[bald] MIRROR READY …` or `[bald] FAIL …`):
* the version file is exactly `6.0.12a`;
* the index file has no newline;
* every asset in the toc has exactly one entry in the hashes file;
* every file has the right size;
* the DLC map has an MP location `z0_mp`, and every pack it names is in the toc.

* every asset the toc lists is present, and no partial `temp_…` download file is left in the folder.

If any check fails, the DLC stays "not downloaded", as before. Nothing is changed, and the log says which file to fix.
The mirror only switches on when the whole set is complete. With a file missing, the game would try to download it
and write partial files into your folder.
