# 06 — Campaign zone unlocks, developer cheats, offline bot matches

Reverse-engineered by the `mc5-zones-cheats-bots` workflow (zones, cheats, matchmaking, the in-match server,
authority and bots; each area adversarially verified), then spot-checked by hand: the zone gate `0x8e2688`, the
zone-table offsets (`0x8e2810`, `0x8e2d60`, `0x64f5f8`, `0x5c2d30`, `0x4f85b0`), the local-match sequence at
`0x8edd64` and its NULL risk at `0x83773c`, and the hook prologues.

## 0 Implemented

* **Zone unlocks.** The server keeps `_inventory.unlocked_zones` (plus the `_inventory_shadow` mirror).
  * The game thread walks the game's own zone table after each 0x24; the walk is read twice and compared. This gives
    `Progress::set_zone_table`, persisted in `state.json` under `zones`.
  * After each 0x11 the server raises U while every story node of zone U is in `progress[]`. The cap is Z−2, or 5
    if Z is unknown.
  * The count is pushed as a silent 0x45 at the next menu return (never in a mission), and again once per
    connection. It is also sent in the login profile.
  * Settings: `campaign.zoneUnlock` (`progress` | `all` | `off`) and `campaign.zoneCap`.
* **Purchases and cheats.** 0x41 and 0x42 are always answered with a silent 0x45, which releases the client's
  purchase lock.
  * `free_xp_1000`, `free_xp_10000` and `free_credits` (`cheats.freeCredits`) are granted.
  * `cheat_unlock_zones` sets U to the cap.
  * Unknown items get `{}`.
  * 0x48 is logged only.
* **Command codes** (Redeem screen; repeatable, no popup):
  * `UNLOCKZONES`
  * `GODMODE`, `INFINITEAMMO`, `INFINITEMEDKITS` (toggles)
  * `CHEATSOFF`
  * `BOTMATCH` (`bots.code`)

  The toggles write settings bytes [0], [5] and [6] (getter `0x4e3498` → `.bss 0x1bbdf28`) on the game thread
  and re-assert them on each 0x10.
* **Local bot match (experimental).** `BOTMATCH` queues the game's own debug sequence for option 0xa0 on the game
  thread. The 132 bytes at `0x8edd64` are fingerprinted, and `*(MP+0xb338)+0x110` is pre-checked. The state is
  "MultiplayerStartLocalGame" (`0x837588`), which makes this client the authority.
  * A hook on the bot tick `0xb083a8` then sets `bm+0x58` = `bots.count` and `bm+3` = 1 for the new bot
    manager.
  * Whether type-0 bots move or shoot is unverified (spec §C3).
* **Quick Play** (`automatch/quickplay*`) answers `[]`. Offline there are no dedicated game servers, and a joined
  client is never the authority.
* **Review hardening** (wf `mc5-m4-review`, each finding adversarially verified):
  * **Walk timing.** The zone walk also runs at the first 0x34 after login. A deferred push about 3.5 s after each
    walk opens a zone the player already earned right away, instead of only after the next mission.
  * **Special zone indices.** Entries for the indices Z..n−1 are skipped instead of rejecting the whole table.
  * **No saves on the game thread.** The game thread never saves: `set_zone_table` only marks the save dirty, and the
    keepalive thread flushes it.
  * **Local-match recovery.**
    * **The failure:** if host init fails, the game retries every frame with a frozen screen.
    * **The exit:** after about 300 frames with our state still on top, the hook leaves exactly the way the game's own
      PopState command does (`0x8376dc..0x837718`: destroy the strings with `0x4226d0`, empty the vector, call
      `MP->vt[0x10]`, pop with `0x82c218`, then clear `MP+0xc4`).
    * **One at a time:** a second BOTMATCH is refused while one is still starting.
  * **Bot arming.** It is consumed by one bot manager. At most 11 bots.
  * **Exception guard.** The pump hook catches exceptions, since the trampoline has no unwind info.
  * **Cheat re-assert.** Cheat bytes are re-asserted at mission start whenever the player made an explicit choice,
    so CHEATSOFF sticks against settings_new.dat.
  * **Command codes.** They respect `redeem.enabled`, and an empty `bots.code` is ignored.
  * **Known, harmless:** `_inventory_shadow.unlocked_zones` is ignored by the client loader, which only reads `upd_`
    keys. The home page then sends one 0x48 per session, which we log.
* **Not done:** a real debug menu (Tier 2, which needs the AS3 value ABI). `has_debug_info_menu` is **not** sent,
  because it only shows an empty INFO page.

---


Target: libMC5 6.0.12a arm64 (build-id 475ac80e…). Addresses are ELF vaddrs unless prefixed `G:` (Ghidra = ELF + 0x100000). Tags used below:
- **[V]**: verified at instruction level by an investigator and a verifier, or by me in this pass.
- **[I]**: inference.
- **[U]**: unverified. Needs a device test.

In this pass I re-checked these against the binary:
- The 0x40 and 0xa0 dispatch inside ELF 0x8eb990.
- The structure of ELF 0x92f5b0.
- ELF 0x8e2688 and ELF 0x8e2810.
- All FNV hashes, which I recomputed.
- The 0x45 framing, against `server/services/profile.cpp::frame_inventory_changes`.

Scratch dumps are in `/tmp/claude-0/-home-user-mc5-offline/ecf49cde-05ff-59c5-bef1-ce361bd597eb/scratchpad/wf6/` (`f8eb990.s`, `f92f5b0.s`).

---

## (A) Campaign zone unlocks (the user's bug)

### A.1 Root cause [V]
The client decides "zone unlocked" in exactly one place, `IsZoneUnlocked(camp, z)` at ELF 0x8e2688. It returns true when any of these holds:
- `z == 0` (`cbz w1`).
- `z` equals one of three special indices: `camp+0x50` (getter 0x6b93b0), `camp+0x54` (0x511db8) or `camp+0x64` (0x86ae70).
- `inventory.count("unlocked_zones") >= z`. Code at 0x8e2720..0x8e274c: `bl 0x4f1858; bl 0x500e90` (pm+0x4b8 = inventory), hash `'unlocked_zones'` = **0x28d0e6a0**, `bl 0x5d5600` (count), `cmp w0,w19; cset w0,ge`.

Nothing on the client ever raises `unlocked_zones`. A full-disassembly search found no movz/movk of 0x28d0e6a0, and every string xref is a read. The requirement rows the user sees as "met" are display only:
- `completedStoryMissions/totalStoryMissions` for zone i counts the type-0 blocks of zone i-1 (G:0x9e2d60, `subs w23,w1,#1` at ELF 0x8e2d78).
- The optional rows come from `game._zones_unlock` (cfg+0x208). Its only readers are the UI builders 0xa53eb0, 0xab6628 and 0xad73c0.

Online, the TS server pushed the new count. Our server never does.

Special indices [V]: n = the number of entries in the zone table `t = *(camp+0xb8)`, stride 0x218. They are +0x50 = n-1, +0x54 = n-5 and +0x64 = n-2. The UI zone count is `Z = n-4` (ELF 0x8e2810: `ldr x8,[x0,#0xb8]; ldp x9,x8,[x8,#0x98]; (len>>3)*0x07a44c6b; sub w0,w8,#4`). Inside the UI range, only index Z-1 is always open.

### A.2 Unlock rule to implement [I: matches the user's memory and the UI]
After each processed 0x11, and once per session at the first 0x24:
```
U = stored unlocked_zones (default 0)
cap = (Z known) ? Z-2 : 5          # cheat targets literal 5 (mov w8,#5 @0x8ed394); Z-2 is [I]
while U < cap and story_nodes[U] is non-empty and every id in story_nodes[U] is in progress[].node:
    U += 1
```
- `story_nodes[z]` holds the node ids (FNV-1a of the level name) of every type-0 (story) block of zone z.
- Types 1 (special), 2 (daily), 3 (arena) and 4 (marksman) do not count. The type table is at G:0x1c00b28.
- Expected after the tutorial: zone 0 = {363515348 (`Venice_01_Intro`, 0x15aacdd4)}, so U = 1 and Zone 1 opens. That zone 0 holds only this node is [U]. The memory walk logs it.
- Never lower U. Never exceed the cap: G:0x9e32e8 and G:0xab6628 show a non-existent chapter when U > Z-2.

### A.3 Profile and storage changes (server/services/profile.cpp)
1. Store `model_["_inventory"]["unlocked_zones"] = U` (an int; `validate()` already accepts non-`_` int keys).
2. Also set `model_["_inventory_shadow"]["unlocked_zones"] = U`.
   - `starter_locked()` writes `_inventory_shadow = {}`. Make sure render and merge keep the key.
   - Without the shadow the home page (ELF 0x9b8258..0x9b834c) sends one 0x48 per session. That is harmless.
3. `progress[]` keeps its format `{"node":FNV1a(level),"objective2":b,"objective3":b}`. Do not add nodes to it for unlocks. The loader G:0x74f210 marks every listed node completed.
4. Login TCP_Profile 0x03 then carries the value. Example fragment:
```json
{"_inventory":{"xp":4200,"credits":0,"diamond_dust":0,"unlocked_zones":1},
 "_inventory_shadow":{"unlocked_zones":1},
 "progress":[{"node":363515348,"objective2":true,"objective3":false}]}
```
5. **Do not send `game._zones_unlock`.** Keep `config_json()` as `{"game":{"_level_up_rewards":[{}]}}` and keep the `game` object; the parser bails out without it (0x607388). Three reasons:
   - The vector at cfg+0x208 is resized to the zone count anyway (0x6099d8..0x6099f8).
   - Values are read with asInt, which asserts on a non-int.
   - A53eb0 drops zones at or above the vector size (0x954c94..0x954ca0).

   Format, for reference only [V]:
   `{"Zone 1":{"servicestars":0,"playerlvl":0,"weaptier":0,"weapcount":0,"sqdmember":0,"openpacks":0,"poweruser":0,"finishmp":0,"prize_name":"<item>","prize_qty":0}}`.

### A.4 Frames
**Unlock push (S→C 0x45, silent)** [V]
- F1=0 (u32), F2=0.0 (f32 LE), F3=0 (u32), F4=0 (u32), then blob32 JSON with the absolute count.
- The handler at 0x5f58e8 takes `cbz w26` at 0x5f5bc8, then 0x5f7858 `bl 0x5d2ba0(inv,json,1)` (SetCount, no catalog needed).
- It stores F1 into pm+0x170 at 0x5f5ac8, which also releases a pending transaction.
- Use the existing `frame_inventory_changes(Json{{"unlocked_zones",U}})`. For U=1:
```
45 002b 00000000 00000000 00000000 00000000 00000014 7b22756e6c6f636b65645f7a6f6e6573223a317d
```
- Never use F1=FNV('endmission') (0xab3ee8ac) or 'zone_unlock_prize' (0x86aac70b). Those take the popup and delta paths.
- 0x12 cannot carry the count: its apply function 0x79a0e8 reads only error/xp/sp/skill_points/cup/solo.

**When to send**
- On 0x11, recompute U. If it grew, set `state_.zones_push_pending = true`.
- On the next **0x24** (menu return), if a push is pending or this is the first 0x24 of the connection and U > 0, send the 0x45.
- Never send it while `pr.in_mission()`.
- The session-start re-push covers cases where no TCP_Profile is sent: gate5a=0, no save yet, or `profile.send=false`.

**Cosmetic loss** [V]: the silent path skips G:0x9e2760. So there is no "new zone" highlight marker (0x6dfb30) and no 0x952b18 call. The zone is still unlocked.

### A.5 meta.cpp switch changes (today lines 532-533 only log, and 0x41/0x42 hang the purchase lock)
```
case 0x24: pr.on_menu_return(); if (auto f = pr.take_zone_push(first_0x24)) m.send_frames(f, "0x45 unlocked_zones");
case 0x41: handle_purchase41(be32(p,0), be32(p,4));      // section B.4
case 0x42: handle_cheat42(be32(p,0), raw4(p,4));         // section B.4
case 0x48: log only ("0x48 item-change claim hash=%08x sub=%u", no reply needed: 0xc0ebe0 sets no lock) [V]
case 0x44, 0x4d: unchanged
```
0x48 layout [V]: `48 0013 | u32 itemHash | u32 sub | u32 0 | u32 0x811c9dc5`. docs/research/04-progression.md line 116 wrongly lists 0x48 → 0x45 error. Fix that doc row.

### A.6 Getting zone→story-node data at runtime (no shipped data)
Add `hosts/embedded/zone_walk.cpp`, in-process and read-only. Read only with the existing `vm_read()` (process_vm_readv cannot fault). Hand the result to the server through a callback, like `g_item_sink`, for example `Progress::set_zone_table()`. Cache it to `<dir>/zones.json`.

Walk [V for offsets, U for the node name at +0x20]:
```
camp = *(*(base+0x1b9aed8))                      # getter 0x4e45c0: adrp 0x1b9a000; ldr [#0xed8]; ldr [x8]
t    = *(camp+0xb8);  n = (*(t+0xa0) - *(t+0x98)) / 0x218;  Z = n-4
beg  = *(camp+0x30); end = *(camp+0x38)          # entries, stride 0x48
for e in beg..end step 0x48:
    zone = i32 *(e+0); type = i32 *(e+4); blk = *(e+8)
    if type != 0: continue
    cnt = i32 *(blk+0x80); arr = *(blk+0x88)
    for i < cnt: node = *(arr+8*i); id = u32 *(node+0x38)
                 completed = u8 *(node+0x6a); unlocked = u8 *(node+0x69)   # log only
                 story[zone].push(id)
```
Validation (reject the walk if any check fails):
- Every pointer is >= 0x1000.
- 0 < n <= 64, and (end-beg) is a multiple of 0x48 with at most 512 entries.
- 0 <= zone < Z.
- 0 < cnt <= 64, and every id is non-zero.

Timing and race rules [V: G:0x9e1858, called from 0x6c3738, frees and rebuilds camp+0x30]:
- Walk only after a 0x24, delayed by 2 s.
- Walk twice, 500 ms apart, and accept only identical results.
- Never walk between 0x10 and 0x11.

Settings overrides:
- `campaign.zones` (a manual table) wins over the walk.
- `campaign.zoneUnlock` takes `"progress"` (default), `"all"` (U = cap at once) or `"off"`.
- `campaign.zoneCap`: 0 means auto.

Fallback when there is no table yet: keep the stored U and log a warning. Do not guess.

Option, not needed: parse `Map_Zones.bin` (VFS name) as a fallback. The top level is three BE i32 counts (nodes, links, groups). Record layouts are only [I], so the memory walk is preferred.

### A.7 Remaining gate to watch [U, rank-1 risk]
Missions inside a newly opened zone need node/group +0x69 "unlocked". That flag is opened only by:
- out-links from completed nodes (0x64f460: node+0x48/+0x50 → link+0x58 target → 0x64ecf8), or
- being listed in progress[].

If Venice_01_Intro has no out-link into Zone 1, the zone opens but its first mission stays locked. The walk logs +0x69 for the first story node of zone U after each unlock, so this is decidable on the device.

---

## (B) Developer cheats

### B.1 The gate [V]
- Byte `game+0x1cb` is read by ELF 0xc14940 (`ldrb w0,[x0,#0x1cb]; ret`). Callers: 0xc14b28 (main menu) and 0xc142d8 (in game).
- Its only writer is 0x613bd0, called at 0x60c330 in the TCP_Config parser. The key is `game.has_debug_info_menu` (bool; the key lives under root['game'], 0x607350..0x60735c).
- When the byte is set, the settings hub adds `debugList=[{"id":"about","name":"INFO"}]`.

**Server flag (preferred, no patch):** `{"game":{"_level_up_rewards":[{}],"has_debug_info_menu":true}}`.

**Equivalent binary patch (not needed):** at ELF 0xc14940, fingerprint `00 2c 47 39 c0 03 5f d6` (ldrb w0,[x0,#0x1cb]; ret). Patch the first word to `20 00 80 52` (mov w0,#1). This is the same style as `apply_libmc5_connected_gate()`.

**Do not enable either one alone** (setting `cheats.debugMenu`, default false). The INFO page is empty: the native answer ELF 0x92f5b0 (registered with '747ab687', GOT slot ELF 0x1b9c270 = base+0x92f5b0) sends 'f87a4850' `{data:{},success:true}` with no controlsList. How the AS3 side behaves with an undefined list is [U].

### B.2 The executor [V]
- G:0x9eb990 (ELF 0x8eb990) handles UI event '2b63dc01' `{optionID:int, value}`. It is registered unconditionally (reloc ELF 0x1b9bc30 → 0x8eb990, read at registration 0xa9a018..0xa9a034).
- Dispatch:
  - The main table at 0x15f65ec covers id-0x25, 0..0xf1.
  - Ids 0x36..0x41 fall to the default at 0x8ed1f0, then sub-table 0x15f69b4 (id-0x3b). I decoded it this pass: 0x3b→0x8ed258, 0x3e→0x8ed2ac, 0x3f→0x8ed2d0, **0x40→0x8ed354**, 0x41→0x8ed3d4.
  - Ids 0x5f+ go through 0x15f69d0 (state 3) or 0x15f6cd8 (other states).

Cheat list (optionID: effect):

| id | effect | server work |
|---|---|---|
| 0x1d | godMode, settings+0x00 (saved) | none |
| 0x20 | infiniteAmmo, +0x05 (saved) | none |
| 0x21 | infiniteMedkits, +0x06 (saved) | none |
| 0x60 | observerMode, +0x01 (in game only, not saved) | none |
| 0x1e / 0x23 / 0x24 | debug bytes +4 / +2 / +3 (+2 changes other toggles' side effects) | none |
| 0x25 | free_xp_1000 → TS 0x41 [0x7731dd40][0] | grant xp+1000 |
| 0x26 | free_xp_10000 → 0x41 [0x137f9750][0] | grant xp+10000 |
| 0x36 | free_credits → 0x41 [0x5426327e][0] (free_BRcredits 0x9f459c2a is dead code) | grant credits+N |
| 0x40 | cheat_unlock_zones: 0x64f4b0 (marks every node completed **in memory**), then if 5-U ≥ 1 → TS 0x42 [0xc1f93cdd][f32 5-U]; needs value asInt==1 (0x8ed35c) | grant unlocked_zones |
| 0x3f | battlepack local SetCount | none |
| 0x27/0x28 | local per-weapon counter +100/+1000 [I] | none |
| 0x29-0x35 | vibration tests | none |
| 0x3c/0x3d | fake FB/GameCenter login error (avoid) | none |
| 0x8e..0x9f | local match map = id-0x8e (0x8d = random) | none |
| 0xa0 | MultiplayerStartLocalGame (section C) | none |
| 0xa1 | LAN client search; 0xa2..0xa4 join a discovered LAN game | none |
| 0x6d/0x6e | in game: forced mission end [I] (races the 0x11 flow; avoid) | none |

Value semantics [V]: 0x25, 0x40 and the others compare `asInt(value)==1`. What a SWF "button" sends is [U].

### B.3 Tiers
- **Tier 0 (do now, no patch).** Serve 0x41/0x42 (B.4). Optionally add redeem codes that grant the same things through the existing 0x53 path, for example `ZONES` → unlocked_zones=cap.
- **Tier 1 (optional): settings bytes from the host.**
  - Fingerprint ELF 0x4e3498 = `c8 b6 00 d0 00 95 47 f9 c0 03 5f d6`.
  - ptr = `*(base+0x1bbdf28)` (.bss). If it is non-null, write bytes [0], [5], [6] (and [1] in game) from `cheats.godMode`, `cheats.infiniteAmmo` and `cheats.infiniteMedkits`.
  - Re-assert on each 0x10 (mission start). These are single-byte writes, so the race is benign [I].
  - The game saves [0], [5] and [6] to `/settings_new.dat` (G:0x5e34a8), so turning a cheat off requires writing 0.
- **Tier 2 (real menu): replace 0x92f5b0.**
  - Before registration at ELF 0xa9d348 (single reader 0xa9dd00 `ldr x2,[x2,#0x270]`), store `our_fn` into GOT slot ELF 0x1b9c270. The slot is in RELRO 0x1ad5fb0+0xd2050, so mprotect it RW and then back to R.
  - Expected current value: `base+0x92f5b0`. Prologue fingerprint: `ff 03 05 d1 fc 83 00 f9 f6 57 11 a9 f4 4f 12 a9`. That is the investigator's G:0xa2f5b0 quote; my dump starts `sub sp,#0x140` = `ff 03 05 d1`, which is consistent.
  - `our_fn(x0=event)` must replicate 0x92f5b0. Its call chain, which I decoded: `0x512600`×2 (values), `0x4e0658`/`0xda8308` (read data.id), `0xd625f0(0x50,0)` + `0xd87e10` (object), `0x4f5cb8` key, `0xdaaaf0` set, `0x5cdf10(v,1)` bool, `0xdbf6f0(*(x0+0x48))`, `0xd7a978(&ctx,"f87a4850",obj,2)` (send).
  - It must add `controlsList` built with the array and push helpers used by the live builder ELF 0x836fa8: G:0xe4bda0 (array), G:0xe4c148 (push), G:0x937428 (set), G:0x5f5c78 / G:0x5fff90 / G:0x6cdf10 (str/int/bool).
  - **This needs a follow-up RE pass on the value ABI [U].** Item shape [V from 0x836fa8]: `{label:str, id:int, value:bool, type:"button"|"switch"}`.
  - Proposed list: `[{"label":"God mode","id":29,"type":"switch","value":false},{"label":"Infinite ammo","id":32,...},{"label":"Infinite medkits","id":33,...},{"label":"+1000 XP","id":37,"type":"button"},{"label":"+10000 XP","id":38,...},{"label":"Credits","id":54,...},{"label":"Unlock zones","id":64,...},{"label":"Local bot match","id":160,...}]`.
  - Only with Tier 2 in place, also send `has_debug_info_menu:true`.

### B.4 Server replies (fixes the stuck `tranzaction_in_progress` lock [V: 0x6202d8/0x620378 set pm+0x170 after a send; the 0x45 F1 store at 0x5f5ac8 clears it])
- Every reply is a silent 0x45 (F1=F2=F3=F4=0) carrying absolute values. Persist the new values with `touch_locked(true)`.
- Parse hashes as BE u32 and log the raw 8 bytes. The f32 endianness in 0x42 is [U], so do not use it; compute the result from U instead.

| frame | hash | reply JSON |
|---|---|---|
| 0x41 | 0x7731dd40 free_xp_1000 | `{"xp":cur+1000}` |
| 0x41 | 0x137f9750 free_xp_10000 | `{"xp":cur+10000}` |
| 0x41 | 0x5426327e free_credits | `{"credits":cur+cheats.freeCredits}` (default 1000; the amount is not in the binary) |
| 0x41 | FNV("skip_unlock_zone_<k>"), e.g. k=1 → 0x20ceb31e | `{"unlocked_zones":max(U,k),"skip_ucrit_zone_<k>":1}`; only reachable if a catalog entry exists [V] |
| 0x42 | 0xc1f93cdd cheat_unlock_zones | `{"unlocked_zones":cap}` |
| 0x41/0x42 | unknown | `{}`: releases the lock with no change. That `{}` is benign is [I] |

- Gate all of this on `cheats.serve` (default true; it is harmless because only the debug menu sends these).
- Setting `cheats.unlockZonesCompletesProgress` (default false): if true, also add every story node to progress[], to match the client's in-memory 0x64f4b0 effect.
- [U] pm+0x138 (the pending-purchase counter, incremented at 0x620350/0x6203f0) may not drop on a 0x45. Test several cheats in a row.

---

## (C) Bot matches: phased plan

Background [V]:
- Online Quick Play always joins as a non-authority. 0xb36980 → 0xb367b8 → 0x8cd650 does `strb wzr,[x0,#0x6c]`.
- The match ran on Gameloft's GS, through a TCP net channel plus a reliable-UDP session (port from GS 0x0f).
- Authority = conn+0x6c (0xac02c0). It is set to 1 only by host init 0x8cd2f0, which is reached only from 0x837588 ("MultiplayerStartLocalGame").
- Emulating the remote GS would mean the UDP handshake (0x01/0x02/0x03/0x17, clock sync) **plus** simulating the whole match. **Not planned.**

### C0: hygiene, now (server only)
1. `matchmaker.cpp quick_join`: branch on `{automatcher}`.
   - `quick_join_ah`: unchanged (the TS room `mc5offline-ts`).
   - `quickplay*` (`quickplayany|quickplaynewplayer|quickplayzombie`): reply `[]`. The client shows a quick 'qpawri' error instead of opening a second controller socket that our meta code treats as a TS (profile frame, unlockAll timer, keepalive flush) and then timing out after 60 s with 'qpte_9'.
   - Log the `filter` and `server_type` fields.
2. `meta.cpp` connect game: if `room_id != "mc5offline-ts"`, log a warning and skip all TS side effects (defensive).
3. Optional: alias the Gaia path `/<cred>/token/encrypt` to encrypt_token. That only matters if Quick Play is ever served.

### C1: start a local hosted match (the client becomes the authority)
The game's own sequence for optionID 0xa0 [V, ELF 0x8edd64..0x8eddec]:
```
mp = 0x4e2108(); 0x836ee0(mp,1)                        # MP+0xc4 = 1
stk = 0x4e04a8()+0x398; st = 0x31fb48(0x40); 0x837558(st); 0x82c0c8(stk, st)
top = 0x834528(0x4e04a8()+0x398)
std::string s; 0x409060(&s); 0x423848(&s,"ChangeState: MultiplayerStartLocalGame",len)   # use game's own string helpers
(*(*top+0x50))(top,&s); 0x4226d0(&s)
```
I confirmed this pass that 0xa0 reaches 0x8edd5c from both state tables: 0x15f69d0[0x41] and 0x15f6cd8[0x41] → 0x8edb6c → 0x8edcac.

0x837588 then [V]:
- mode = `(*(0x6b8cc8(MP)+0x110))+0x14` (no null check).
- map = settings+0x3c, or `rand()%4` if negative.
- timer 1800000 ms; `0xb365e8(MP,0x0ac25278,…)` → conn+0x6c = 1, LAN mode, UDP "7891".
- It bails out if host init fails (0x83785c).

Ways to trigger it, all on the **game/UI thread**:
- **(a) With Tier 2:** the "Local bot match" button (id 160). The game runs it itself. Best option.
- **(b) Without Tier 2:** wrap the '2b63dc01' handler pointer (RELRO reloc ELF 0x1b9bc30; patch before registration at 0xa9a018).
  - The wrapper calls the original handler, then runs the sequence above if `g_pending_local_match` is set.
  - The server sets the flag on a redeem code (setting `bots.code`, default `"BOTMATCH"`; reply 0x54 as for a valid code).
  - The player then toggles any setting. This is the same context the debug menu uses.
- Pre-checks before running (via vm_read):
  - `MP=*(*(base+…0x4e2108 target))` is non-null.
  - `*(MP+0xb338)` and `*(*(MP+0xb338)+0x110)` are non-null [V crash risk]. If either is null, log "open the Multiplayer menu first" and refuse.
  - Map choice: optional, by replaying option 0x8e+idx (not needed; random 0..3 is fine).

Log: wrapper hit (tid), pre-check values, "local host sequence pushed", and any `getaddrinfo(NULL,"7891")` passing through `my_getaddrinfo`.

Test: the map loads with the player alone and the authority byte reads 1 (vm_read `*(*(MP+0x10)+0x6c)`).

### C2: bots
- The bot tick ELF 0xb083a8 (x0 = bm = `*(MP+0xb340)`) is called every frame from 0xb06d00, only while the client is the authority, the match is not over and bm is non-null [V].
- It calls 0xb41a80 if `bm+0x58>0 || bm+0x5c>0 || bm+0x60>=1`. Nothing in the client sets these to non-zero values [V for immediate stores].
- The bot "team" argument is really a **type**. c42270 allows one bot per type ≥1 (0xb422d8..0xb42394) [V]. So `bm+0x60=N` yields one bot.

Implementation:
- Put a continuation hook on 0xb083a8 entry. First check that its first 4 instructions pass `reloc_safe` [U].
- Callback, once per bm pointer: if `*(bm+0x20)` (bots data) is non-null, set `*(i32*)(bm+0x58) = bots.count` (default 6) and `*(u8*)(bm+3) = 1` (arms the type-0 fill; on a host w21 ≤ 0 [V]). Optionally set `*(i32*)(bm+0x60) = 1` for one type-1 AI bot.
- Keep `MP+0x188f == 0` (0xb41aa8 early return).
- Fill happens at most one bot per frame, gated by the timers at bm+0xc/+0x14/+0x18/+0x1c [V].

Log: bm, `bm+0x20`, counts before and after, and the player-count delta every 5 s.

Test: bots appear with names from bots.bin. **Whether type-0 bots move or shoot is [U].** be5928 attaches AI only for types 1, 2 and 3 (controllers 0xb47c58, 0xb3e570, 0xb489d8).

### C3 (conditional): bot AI
If type-0 bots stand still, the fallbacks are:
1. Use types 1, 2 and 3 only, which gives up to 3 AI bots (`c42270(bm,1..3)` on the game thread). Types 2 and 3 have empty names, and their semantics are [U].
2. RE be5928's type-1 branch and attach a 0xb47c58 controller to each type-0 bot.

### C4: match end
- MP never sends 0x11 (the builder 0xc0c2d0 is campaign-only [V]).
- Log every TS frame type seen between the local-host start and the next 0x24.
- 0x19 (achievements) may be routed to the absent GS socket and dropped while MP+0xc4 is set [I].
- Decide on rewards after seeing the data.

### C5 (later): UI entry
Route Multiplayer → Quick Play into C1: the matchmaker sees `quickplay*` and sets the pending flag. This needs a game-thread trigger that does not collide with the running Quick Play FSM. Out of scope until C1 and C2 work.

---

## (D) Risks and unknowns, ranked
1. **[U] Zone 1's missions may stay locked** even with unlocked_zones=1, if no link-graph edge opens their +0x69 (A.7). Detect with the walk log.
2. **[U] Type-0 bots may have no AI** (C2/C3).
3. **[V] Race in the memory walk** (0x9e1858 frees and rebuilds the entries). Mitigations: process_vm_readv only, a delayed double read, strict validation, and the manual fallback `campaign.zones`.
4. **[V] Null derefs on the local-host path**: `MP+0xb338`→`+0x110` in 0x837588, `bm+0x20` in c41a80 and c42270. Pre-check them; run only on the game thread.
5. **[I] Cap = Z-2** (Z-1 is always open). The fallback is 5. A cap that is too high shows a phantom chapter.
6. **[U] Patch timing.** The GOT and reloc swaps (0x1b9c270, 0x1b9bc30) must land before registration (0xa9d348, 0xa99c20). Log the wrapper's first hit; if the original pointer was already copied, the swap is a silent no-op.
7. **[U] Tier 2 value-builder ABI** and what a SWF "button" sends (`value` must be asInt 1).
8. **[U] pm+0x138 pending counter** may grow with every purchase.
9. **[U] The `{}` reply for unknown purchases**, and whether an xp SetCount triggers level-up rewards correctly.
10. **[I] UDP broadcast** (SO_BROADCAST on 7891) in host init may fail under our socket hooks or Android policy, and then 0x837588 bails out.
11. godMode, ammo and medkits persist in settings_new.dat. The cheat 0x40 marks all nodes completed in memory only, so the client and our progress disagree until the next login.

## (E) Device-test checklist (new log lines are proposed; names in quotes)
1. **Fresh boot, tutorial already done (existing save):**
   - `[zones] walk ok: Z=<z> cap=<z-2> zones={0:[363515348],1:[…],…} (2 identical reads)`
   - `[zones] recompute: U 0 -> 1 (zone 0 complete: 1/1 story nodes)`
   - `meta#N 0x45 unlocked_zones=1 (silent, first 0x24)`
   - Expected: Zone 1 shows unlocked, and so does the always-open index Z-1.
   - Also check `[zones] zone 1 first node <id> +0x69=<0|1> +0x6a=0`. A 0 here means risk D1 is real.
2. **Restart the app:** TCP_Profile contains `"unlocked_zones":1`. No 0x48 appears in the log (the shadow is mirrored). Zone 1 is still open.
3. **Finish all of Zone 1's story missions:** after the last 0x11, `[zones] recompute: U 1 -> 2 (pending)`, then on the 0x24 `0x45 unlocked_zones=2`. Never during a mission: check that there is no 0x45 between 0x10 and 0x11.
4. **Cheats via Tier 2 or a debug build** (with `has_debug_info_menu`):
   - `meta#N 0x41 free_xp_1000 (7731dd40) -> 0x45 {"xp":…}`, the XP bar updates, and a second cheat right after also works (lock released).
   - `0x42 cheat_unlock_zones -> 0x45 {"unlocked_zones":5}`.
   - Unknown hash: `0x41 unknown <hash> -> 0x45 {}`.
5. **Tier 1:**
   - `[cheats] settings@<ptr> godMode=1 ammo=1 medkits=1 (fingerprint ok)` on 0x10.
   - In a mission: no damage taken and ammo is not consumed.
6. **Quick Play (C0):**
   - `matchmaker: quickplay automatch 'quickplayany' filter='_game_mode=…' -> [] (local bots use the local-host path)`.
   - The client shows an error within about 1 s. There is no second meta# connection.
7. **Local match (C1):**
   - `[localmp] 2b63dc01 wrapper hit tid=<main>`, `[localmp] pre-check MP=… b338=… +0x110=… ok`, `[localmp] StartLocalGame pushed`.
   - `getaddrinfo(NULL,"7891") passthrough`.
   - The map loads. `[localmp] authority=1`.
8. **Bots (C2):**
   - `[bots] tick bm=<p> data=<p> set 0x58=6 bm+3=1`, then `[bots] players=2..7` growing about one per frame or timer interval.
   - Watch whether they move. If they do not, go to C3.
9. **Match end (C4):** frame-type histogram `[localmp] post-match TS frames: …`.

The spec is in this message only; I did not edit any repo file. My disassembly dumps from this pass are `/tmp/claude-0/-home-user-mc5-offline/ecf49cde-05ff-59c5-bef1-ce361bd597eb/scratchpad/wf6/f8eb990.s` and `/tmp/claude-0/-home-user-mc5-offline/ecf49cde-05ff-59c5-bef1-ce361bd597eb/scratchpad/wf6/f92f5b0.s`.

Files the changes touch:
- `/home/user/mc5-offline/server/services/profile.cpp` and `.hpp`: U, shadow, zone table, push-pending, settings.
- `/home/user/mc5-offline/server/services/meta.cpp`: 0x24 push, 0x41/0x42/0x48 handling, room_id guard.
- `/home/user/mc5-offline/server/services/matchmaker.cpp`: the quickplay branch.
- `/home/user/mc5-offline/hosts/embedded/` (new `zone_walk.cpp`, plus additions in `patch.cpp`): settings bytes, GOT/reloc wrappers, bot tick hook.
- `/home/user/mc5-offline/docs/research/04-progression.md` line 116: correct the 0x48 row.