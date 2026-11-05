# 04 — Progression, currencies, unlock codes, and the profile-stats crash

Reverse-engineered from the client's own code (libMC5 6.0.12a arm64) by the
`mc5-progression-unlocks` workflow (five areas, each investigated and then adversarially
verified), then spot-checked by hand (0x628af8 bytes and patch disassembly, the 0x607388
early exit, TS cases 0x07/0x12/0x45/0x54, FNV sign extension). **§9 says what is
implemented** and how it differs from this spec.

Scope: libMC5.so 6.0.12a arm64. Every address is an ELF vaddr unless it has a `G:` prefix (Ghidra address = ELF + 0x100000). Repo: `/home/user/mc5-offline`, branch m0. Device evidence comes from build d86ee5c (`fd53be1d-mc5offline.log`, `be5d5593-crash-…05_11-10-05-03_178.log`).

The spec writer re-checked these points in the disassembly or decomp during this pass. Each is marked **[re-checked]** where it is used:
- 0x628af8 bytes and semantics.
- The MP gate on the post-mission b2 clear (0x4ed160 = `ldrb w0,[x0,#0xc4]`; the 0x19 builder 0xc0d250 routes to GS 0xbf2570 when it is set).
- The outcome-controller wait at 0x80effc..0x80f00c.
- The app ctor `strh 0x101 → [app+0x6f4]` at 0x4e2510.
- TS cases 0x12, 0x45/0x46 and 0x54 (decomp 00d0.c:10792, 11273, 11327).
- The 0x12 apply logic G:0x89a0e8.
- The skills loader G:0x89bc60 (literal keys).
- The achievements loader G:0x898680 and its key builder G:0x8985e0.
- The ks table layout at 0x83a710.
- Inventory count 0x5d5600.
- The armory and catalog accessors.
- The 16-byte prologue relocatability of every hook site listed in §6.

---

## 1 Diagnosis

### 1.1 Profile → stats crash (SIGSEGV addr 0 at 0x95e6ec)

**Root cause: our TCP_Config 0x3e payload `"{}"`. The missing TCP_Profile is not involved.**

1. `server/services/meta.cpp:241` sends `3e 00 09 | 00000002 7b7d`. The 0x3e handler queues config job type 1, which runs on the main thread: pump 0x5f5128 (called from 0x4eed80 at 0x4eef64) → 0x5f52d0 → 0x607270(cfg, root). cfg is `*(*(base+0x1b9b0c8))` (getter 0x511560).
2. 0x607270 first clears the item catalog at cfg+0x18..+0x20 (0x6072d4..0x607304). It then has exactly two early exits to 0x60d554 (return 0): root null at 0x6072d0, and `root["game"]` null at **0x607388**. `"{}"` takes the second exit.
3. Because of that early exit, 0x614c78 never runs (its only call site is 0x60d4fc, called with `game["_level_up_rewards"]`). 0x614c78 is the only writer of the `vector<vector<{u32 hash,i32 qty}>>` at cfg+0x5f8, which it resizes to `size(json)+1`. The table therefore stays `{begin=0,end=0}`.
4. Accessor 0x628af8(cfg, lvl) **[re-checked]**: `cmp w1,#0; b.le → ldr x0,[x0,#0x5f8]`. Otherwise it computes `size=(end-begin)/0x18` and returns `csel(begin+lvl*0x18, begin, size>lvl)`. With an empty table it returns `begin` = NULL.
5. 0x95cb20, the profile-stats page builder (AS3 native `4ae0ca3b`, thunk 0x95ee80 → `b 0x95cb20`), loops `w22 = 2 .. maxLevel` (0x95e6b4). It calls `bl 0x4e04a0` (cfg), then `mov w1,w22; bl 0x628af8`, then **`ldp x8,x9,[x0]` at 0x95e6ec**. The tombstone shows x0=0, x1=x22=2 and lr = return address of the bl at 0x95e6e8.
6. The same NULL dereference is reachable from:
   - 7 other callers of 0x95cb20 (popup-close refresh paths): 0xa2e018, 0xa2f2f8, 0xaa6fa0, 0xa4e130, 0xaa68e0, 0xaa8260, 0xb872b8.
   - The two level-up reward popups 0x941738 and 0xa3e820. These are reached only from config job type 3 (0x5f58e8), which is fed by S→C **0x45/0x46 TCP_Inventory_Changes** (call sites 0x5f8f84, 0x5fb5d4, 0x5fbd94, 0x5fd3e0). So once we push inventory changes they crash the same way.
7. The device's `/hc.dat` now caches `"{}"` (0x5f5778 writes it after every type-1 job). The next non-empty 0x3e overwrites it.

### 1.2 BALD request storm (2680 GETs of `bald_android_astc_h___index` in about 70 s)

- This is Gameloft's BALD runtime-DLC manager (wrapper ctor G:0xc619d8; BALD ctor G:0x136cfc8). It is named `"android"` + `_astc|_etc` + `_h|_l`; the suffix is built by the caller G:0xc61858. Version `6.0.12a`, directory `<files>/bald/`, recheck interval 1,800,000 ms, 2 `BaldDLC` workers.
- Worker G:0x1373a00, case 1: **any** non-zero result from GetAsset G:0xd8d810 increments `DAT_01d3b5f0`, prints a WARNING and sleeps `(1*10+10)` ms. The outer worker loop then sleeps another 1 ms. There is no cap, no backoff and no status-code distinction, so 404, 5xx, timeouts and refused connections all retry forever. Each retry opens a new TCP/TLS connection.
- A `{}` reply with status 200 only moves the storm to `bald_…__toc_{}`. A toc with no `map_android_dlc` asset makes BALD ready, and then the wrapper tick G:0xc61e28 case 0 pushes the NULL lookup result and dereferences it in G:0xc64570 → `ldr w8,[x0,#4]` at ELF 0x8e1728: SIGSEGV at address 0x4. The resume path G:0xc62348 does the same.
- BALD gates nothing we use: boot, campaign and menu all ran with BALD never ready. The only cost is CPU and battery.

### 1.3 Why both currencies show -1

- **In-game CREDITS** (soft, green) is inventory item **`diamond_dust`**. **In-game GOLD** (hard) is inventory item **`credits`**. Evidence: gift handler 0x5e7340 sends `soft_currency`→diamond_dust and `hard_currency`→credits; the reset_* paths match.
- `-1` is not a game value. It is the SWF TopBar placeholder: e047 m581296 does `$sc={value:0,currentValue:-1}`, and `$hc` is set the same way. An absent inventory item reads as **0**: 0x5d5600 returns `wzr` on a miss. The labels keep the placeholder because `GameSettings.getAmount('sc'/'hc')` was never fed (m523452 `onTopBarData` reads it).
- The native path that fills GameSettings sc/hc is **not identified**. The native top-bar builder G:0x9efb50 (ELF 0x8efb50) sends ks-keyed `credits` (count of `credits`) and `rc` (br_currency) but no diamond_dust. `CPP_SEND_INVENTORY_DATA` (`0bf39f26`, sender G:0xac51f0) is the cores/consumables page.
- Most likely contributors, all fixed by §2:
  - (a) No profile was ever applied, so the post-apply refreshes in G:0xd08fb0 never ran.
  - (b) The catalog cfg+0x18 is empty, so 375 lookups through 0x5d5198 return NULL.
- Verification criterion for the next round: the bar shows real numbers after a 0x03 that carries `_inventory.diamond_dust/credits` plus a config with `"game"`. If it does not, use the §6 top-bar tap.

### 1.4 What the save path is

There is **no client-side save** in this build.
- The app ctor hard-sets the "TS online" byte at **0x4e2510 `strh w8(=0x101),[x19,#0x6f4]`** **[re-checked]**. Nothing else writes it.
- With that byte set, the client skips its offline path (local XP/SP/stats merge G:0x8997b0 and local outcome screen G:0x900238).
- Profile keys are only **read** (loader 0x4f18a0 → 0x5e1498, 0x5d0ec0, 0x7a13c0/0x79bc60, 0x64ed80/0x64f210, 0x798680, 0x5dd9c8, 0xab1b60, 0x4f1a28). No serializer exists.
- The client uploads small deltas over TS (0x16, 0x17, 0x19, 0x1a, 0x32, 0xa3, 0x59, 0x0b, 0x10/0x2d, 0x11/0xac). It gets the whole document back as TCP_Profile 0x03/0x27 at login.
- **Today our server drops everything, so every restart is a fresh account** (age gate and tutorial again). The only client-local files are `/legal.dat` (age), `/hc.dat` (config cache), `bald/`, and the IRIS caches.

### 1.5 Why the mission-end stats screen never loaded

- At mission end the client sends 0x11 (builder 0xc0c2d0; device log +220114 ms, len 833). It then waits for **S→C 0x12 [str JSON]**:
  - TS case 0x12 → event 7 → G:0x89af60, which sets `achMgr+8 = 1` and applies through G:0x89a0e8.
  - The outcome controller 0x80ef40 polls with no timeout: `ldrb w8,[app,#0x6f4]; cbz` → `bl 0x4e5f58; bl 0x496020 (ldrb [x0,#8]); tbz w0,#0,0x80f184` **[re-checked]**.
  - We never answer 0x12.
- The b2 clear in 0x8352a0 cases 0/10 runs only when 0x4ed160 (`ldrb [x0,#0xc4]`, the MP-match flag) is set **[re-checked]**. It is irrelevant in the campaign, so no post-mission 0x22 is needed.
- Side effects of the missing 0x12:
  - Achievements earned in the mission were never unlocked locally (G:0x88f748 runs only after 0x12).
  - The node did not complete. The second 0x10 at +280020 ms is the same node, 363515348.
- Also seen: a 15 s stall after 0x06 `Story_01.lvc` (+228571 ms). The level loader waits up to `gate+0x40 = 15000` ms (0x82fad4..0x82fb00) for 0x07/0x29.

---

## 2 Exact server behaviour

Framing: `[type u8][len u16 BE incl. 3-byte header][payload]`. `str` = u16 BE length + bytes. `blob32` = u32 BE length + bytes. All u32 values are BE unless stated. Generate frames only with `ts_frame()`/`blob32()`, never by hand.

### 2.1 Client → server frame table

"Persist" means: update the in-memory model, mark dirty, save (§3).

| Type | Payload (as parsed) | Reply | Persist / action |
|---|---|---|---|
| 0x01 InitSettings | as decoded by `decode_init_settings`; note `identity`=country (device `CA`) and `gate5a` | **burst §2.2** | store country, gate5a |
| 0x49 | — | `4a 00 07 00000000` (existing) | — |
| 0x96 | — | `22 00 03` (existing) | set "ignore next 0x16 op0" |
| 0x21 | `u8 flag` | `22 00 03` | set "ignore next 0x16 op0" |
| 0x50, 0x34, 0x52, 0xad, 0xa8, 0x69, 0x74, 0x5a | known fire-and-forget | none | 0x74 marks "profile frame received" (not "applied") |
| 0x59 | `u32 age, u32 gender` (1 = male, 2 = female; device 0x14, 2) | none | `age`, `gender` ("male"/"female"), `birthdate = "<year−age>-01-01"` |
| 0x0b | `str {"display_name":"SOLDIER_44725"}` | none | `alias` |
| 0x10 | `str {"level":"Venice_01_Intro","node":363515348}\n` (mission **start**) | none; **never** send S→C 0x10/0x2d with u32≠0 (error path G:0xc80d38) | `cur_node`, `cur_level`, `in_mission=true`, `mission_seq++` |
| 0x2d | same JSON (re-sent after a reconnect by G:0xd08bd0) | none | same as 0x10 (idempotent) |
| 0x06 | `str lvcName, u32 cachedVer (ffffffff)` | **`07 00 07 00 00 00 00`** immediately | log only |
| 0x11 | `str triples; str statsJSON; u8 n1 + n1×blob32(24 B LE {u32 id,kills,hits,shots,timeUsed,score}); u8 n2 + n2×blob32(12 B {id,kills,score}); u8 n3 + n3×blob32(12 B {u32 achId,u32 tier,u8 sync,3 pad}); u8 n4 + n4×{str cat,str info,u32 key,u8 del,u8 mask}` | **`12 LL LL | str {"xp":X,"sp":Y}`** immediately, on every receipt including duplicates | see §2.1.1; the apply is de-duplicated, the reply is not |
| 0xac | `str statsJSON` (mission ended without success; device `{"time.played":1}`) | none | `statistics.sp[k] += v` (integer values only) |
| 0x24 | — (back in the menu after a level) | none | `in_mission=false`; flush deferred pushes |
| 0x16 | `u8 mode, u8 idx, [str loadoutJSON if mode==1]` | none | mode 1: `inventory.loadouts[idx] = JSON` (must parse to an object; **a mode-1 frame without the string means the client's 1 KB writer overflowed: keep the old entry**). mode 0: `inventory.current_loadout = idx`, **except** the first mode-0 frame after each S→C 0x22, which carries the pre-load index and is ignored |
| 0x17 | `u8 class, u8 skillIndex, u8 tier` (1 or 2; device `00 00 01`) | none | `skills_raw[class][skillIndex] = tier`. The frame carries no cost (§3.3) |
| 0x19 | `u32 achId, u32 tier, u8 sync` (device id 11, tier 0) | none | `ach_raw[(id,tier)] = {sync}` (dedup) |
| 0x1a | `str name, str data, u32 value, u8 flag, u8 op` (op 5 add/update, 1 remove by name, 3 remove name+data, 7 add variant) | none | `notif_raw` list (not emitted in v1) |
| 0x32 | `u8 n=3, n×u8 pending` (device `03 00 01 01`, then `03 00 00 01`) | none | `menu_tutorials = [bool×3]` (true = pending) |
| 0xa3 | `u8 difficulty` | none | `sp_difficulty` |
| 0x66 | — (killsig/cup unlock condition) | none | log |
| 0x53 | `str code` | §4.3 | §4.3 |
| 0x41 | `u32 itemHash, u32 qty` | 0x45 (§2.5) | §2.5 |
| 0x42 | `u32 itemHash, f32 LE qty` (e.g. `cheat_unlock_zones`) | 0x45 (§2.5) | §2.5 |
| 0x44, 0x4d, 0x48 | format not mapped | 0x45 error (§2.5) | log full payload |

Parser rules:
- Parse every frame field by field with a bounds check. The client's builders ignore the overflow flag, so a refused string or blob can vanish **from the middle** of a frame while later small fields are still written.
- For 0x11, validate as you go: u16 lengths must fit; str2 must start with `{`; blob lengths must be exactly 24/12/12. On misalignment, stop parsing that section, still reply 0x12 computed from whatever statsJSON was recovered, and log the frame in full.

#### 2.1.1 0x11 apply (once per distinct payload)

- `key = FNV-1a-32(payload bytes)`. If `key` is in `state.seen_0x11` (keep the last 64), skip the apply and only re-send 0x12. The client re-sends an identical 0x11 after a TS reset: flag gate+0x92 is set by G:0xccd410 from reset handler G:0xc80dc0.
- `X = int(xp.rewards)+int(xp.medals)+int(xp.objectives)` (missing = 0), multiplied by `economy.xpMultiplier` and rounded. `Y = int(sp.value)` multiplied by `economy.spMultiplier`.
- `_inventory.xp += X`; `_inventory.skill_points += Y`.
- Triples `"type:id:count:"` (device `0:4155398577:4:0:73300843:16:…`):
  - type 0 = medal {hash, count};
  - type 1 = objective {1|2|3, 1}; ids 2 and 3 set `objective2`/`objective3`;
  - type 2 = list at mission+0xa8.
- `progress` gets or updates `{node:cur_node, objective2, objective3}`, OR-merged.
- Weapon records go to `inventory.weapons[name]{kills,hits,shots,time_used,score} +=`, where name = the armory name whose FNV equals `id`. Skip unknown ids.
- Achievement records go to `ach_raw` (these unlock on the client only after a successful 0x12).
- statsJSON integer entries go to `statistics.sp[k] +=` (placement is an unknown, §7).
- Reply JSON must **never** contain `"error"`; that shows "popupProgressNotSaved". Example: `{"xp":150,"sp":2}` → `12 00 16 00 11 7b227870223a3135302c227370223a327d`.
- If `economy.missionCredits > 0` (default 0, experimental), queue a §2.5 0x46 `{"diamond_dust": new}` after the 0x12.

### 2.2 Login burst and TCP_Profile rules

The burst is sent once, in a single write, right after the first 0x01. **Only the 0x3e payload changes, and the profile frame is inserted.** Otherwise the order of the device-proven burst is kept:

```
22 00 03                                                     b0,b2 (then ignore the next 0x16 op0)
3e 00 2a | 00 00 00 23 | {"game":{"_level_up_rewards":[{}]}} b3 + level-up table (35-byte JSON)
[profile frame, only if the rules below allow it]
04 00 0a | 00 | 00 00 00 02 5b 5d                            b1 (event 2)
4a 00 07 | 00 00 00 00                                       b4
```

Full 0x3e frame: `3e 00 2a 00 00 00 23 7b2267616d65223a7b225f6c6576656c5f75705f72657761726473223a5b7b7d5d7d7d`. `{"game":{}}` is also sufficient, since 0x614c78 resizes to size+1 even for null. If `_level_up_rewards` is sent it must be an **array**: element k = rewards for level k+1, `{"<item>":qty}`, unknown items skipped. Never include `iap.prices` (0x5f52d0 routes it through 0xc6f788). Never send `"ERR"` or `""`. The JSON must be valid: 0x5f52d0 ignores the parse result and would cache the bad text.

The profile frame is sent only when **all** of these hold:
1. InitSettings `gate5a == 1`.
2. `profile.json` exists **and** `age >= 0`. On the very first run (nothing stored) no profile is sent; that is the device-proven path.
3. `settings.profile.send` is true, and env `MC5_TS_PROFILE != 0`.
4. The rendered JSON passes the §3.4 validator.

Choice of frame type:
- Raw JSON ≤ 65,528 B → **`03 LL LL | u32 n | JSON`**.
- Otherwise → **`27 LL LL | u32 clen | LZ4 block`**, with clen ≤ 65,528 and raw ≤ 1,048,574 (0xffffe, so the 1 MB buffer stays NUL-terminated).
- The JSON must contain no NUL.
- 0x27 **needs a real LZ4 compressor**. The existing `lz4_store()` writes literals only and makes the data larger.

Timing rules:
- Never send a profile mid-session or after a mission. A load resets age (0x5dffd8 writes −1 to pm+0x58 and 0 to gender), resets ratings to 800, and clears and rebuilds the inventory (0x5ce9a8).
- A TS error reset sets gate5a=1 again (G:0xc80dc0 cases 2, 5, 6). The next InitSettings then legitimately gets the up-to-date document.
- The 0x74 ack is sent by the network thread before the apply, so it does not prove the apply worked. The apply is confirmed when gate+0x5a clears (§6 poller).

### 2.3 Minimal safe starter profile (verbatim)

This is the document rendered after the first session in which only the age gate passed. Values come from the device run.

```json
{"_initial_country":"CA","created":"2026-11-05T09:59:50Z","alias":"SOLDIER_44725","age":20,"gender":"female","birthdate":"2006-01-01","sp_difficulty":0,"rating":800,"rating_duel":800,"best_solo_rank":0,"best_squad_rank":0,"best_rating":0,"private_profile":false,"statistics":{"general":{},"sp":{},"mp":{}},"_inventory":{"diamond_dust":0,"credits":0,"xp":0,"skill_points":0},"_inventory_shadow":{},"inventory":{"current_loadout":0,"weapons":{}},"progress":[],"achievements":{},"menu_tutorials":[true,true,true],"menu_tutorials_skipped":false,"daily_reward":{"day":0},"br_daily_reward":{"br_day":0}}
```

Type rules, each of which is a crash if violated:
- root, `statistics.*`, `_inventory`, `_inventory_shadow`, `inventory`, `daily_reward`, `br_daily_reward` and `achievements` are objects.
- `progress`, `menu_tutorials` and `inventory.loadouts` are arrays.
- `private_profile` is a bool. The current `default_profile()` sends `{}`, which jsoncpp's asBool rejects.
- Every `_inventory` value is an int in [0, 2^31−1].
- `progress[i].node` is numeric (FNV-1a of the level name).
- `inventory.loadouts[i]` is an object exactly as uploaded by 0x16 mode 1. Emit only the contiguous prefix 0..k of known slots; never synthesize one; omit the key when there is none.
- Do **not** emit top-level `credits`/`rd_currency` (ignored), top-level `event_*` (they live inside `tournaments_sem[]`), `notifications`, or `skills` / name-keyed `achievements` entries until §6 dumps give names. `birthdate` non-empty stops the 0x59 re-send loop (loader sets pm+0xa8=−1).

Literal key names are valid for the hashed keys: `bodyitems` is proven on the wire, and the rest is confirmed by the §6 ks dump.

### 2.4 BALD replies (`server/services/asset.cpp`)

Match `<n>` = `android_(astc|etc)_(h|l)`. All three replies are status 200, `Content-Type: application/octet-stream`, exact bodies, no trailing newline, same answer with or without `Range`. There must be no dependency on connection reuse, because every retry is a new connection.

| GET `assets/{cid}/…` | Body |
|---|---|
| `bald_<n>___index` (3 underscores) | `1` (1 byte, constant forever; it is byte-compared with `bald___index___.txt`) |
| `bald_<n>__toc_1` (2 underscores) | `{"hashes":[{"name":"bald_<n>_map_android_dlc_1","file_size":6,"chunk_size":65536,"hashes":["04ec0d2d9673bcf019d62fdc9f3e6e09"]}],"toc":[{"_version":"6.0.12a","assets":[{"name":"bald_<n>_map_android_dlc_1"}]}]}` |
| `bald_<n>_map_android_dlc_1` (request carries `Range: bytes=0-5`) | `<dlc/>` (3C 64 6C 63 2F 3E; md5 04ec0d2d9673bcf019d62fdc9f3e6e09). This is self-authored, not Gameloft content |
| any other `bald_*` | 404 plus a `logw` (it would storm; it should never happen) |

- The key extraction gives `map_android_dlc`, which matches `map_android.dlc` once lowercased and with '.' replaced by '_'.
- The DLC state then runs 4→5→1 and parks. It reaches 6→2 once the menu sets +0x3c. No popup, no packs.
- Later boots: one index GET, then one every 30 min.
- About 1 MB of free disk is required (G:0xc92a78).
- Never serve an empty `assets` array or a toc without the map entry: that crashes at address 0x4.

Other HTTP: unchanged. Storage consent stays `200 {}`. MC5 has no Iris `/coupons/` call (the string has no code xref), so the codes use TS (§4).

### 2.5 S→C push frames

**0x45/0x46 TCP_Inventory_Changes** (handler 0xc0984c; decomp case 'E'/'F' **[re-checked]**):

```
45 LL LL | u32 F1 | f32 LE F2 | u32 F3 | u32 F4=0 | u32 n | JSON
46 LL LL | u32 F1 | f32 LE F2 | u32 F3 | u32 F4=0 | u32 clen | LZ4 block   (≤1 MB raw)
```

- Silent grant: F1=0, F2=0.0, F3=0, F4=0 (cbz w26 at 0x5f5bc8 → apply 0x5f7858).
- JSON = a flat inventory object `{"<item>":absoluteCount,…}`, applied by 0x5d2ba0(inv, root, 1) → SetCount 0x5cf5d0. There is no reset; count 0 removes the item. Do not include `_`-prefixed keys or `boosts`.
- Each frame writes pm+0x170 := F1, which clears the "tranzaction_in_progress" marker.
- F1 values other than 0 are reason hashes (`shop_gift`, `pwrusr_gift`, `social_gift`, `IAP_UNKNOWN`, `endmission`, `endmission_rwd_sp`/`_mp`) and drive popups that perform catalog lookups. Do not use them in v1.
- F4≠0 → error path 0x623b58 (F4=10 with F1=hash("survey_update") is dropped).
- Purchases (0x41/0x42/0x44/0x4d/0x48): answer every one, since only one transaction can be outstanding.
  - v1 default: `45 00 13 | F1=0 | F2=0 | F3=0 | F4=1` (error, releases the lock with "tranzaction_error").
  - With `economy.freePurchases=true` and a resolvable item name: a 0x45 F4=0 `{"<item>":count+qty}`. Persist it.

---

## 3 Persistence design

### 3.1 Location and files

- `<files>` is the directory `diag::open_log_copy()` picks: `/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files` first (pullable with `adb pull`, survives updates, not uninstall), then `/data/data/com.gameloft.android.ANMP.GloftM5HM/files`.
- Root: **`<files>/MC5Offline/`** (mirrors MCVS `…/files/McvsOffline/`).

| File | Content |
|---|---|
| `settings.json` | flags (§4.5); created with defaults if missing |
| `profile.json` | the **model** (exactly the keys of §2.3 plus `inventory.loadouts`), rendered to the client verbatim |
| `state.json` | server-only: `{"version":1,"redeemed":{CODE:{"at":iso,"items":n}},"unlockAllDone":bool,"seen_0x11":[u32…],"cur_node":u32,"skills_raw":{"c.s":tier},"ach_raw":{"id.tier":sync},"notif_raw":[…],"client_counters":{…},"sp_earned":int}` |
| `*.bak` | the previous good copy of each |
| `dumps/` | `ks.json`, `catalog.json`, `armory.json`, `achievements.json`, `skills.json` (§6; also the item universe for §4) |

### 3.2 Write discipline

- One `ProfileStore` with one mutex.
- Save = write `x.tmp`, `fsync`, rename the old `x` to `x.bak`, rename `x.tmp` to `x`.
- Save immediately on 0x11, 0x53 and 0x59; on other frames, debounce 1 s; always save on meta-connection close.
- Load order: `x`, then `x.bak`, then fresh. A file that fails to parse is moved to `x.broken-<epoch>` and never overwritten silently.
- Write-ahead for grants: the ledger and inventory are saved before any 0x46 push.

### 3.3 Merge rules

The server is authoritative for everything it computes. The client is authoritative for what only it knows.

| Field | Rule |
|---|---|
| `_inventory.xp` | server `+= X` per de-duplicated 0x11. The tap value is logged on mismatch only |
| `_inventory.skill_points` | v1: `sp_earned` (0x12 sp plus achievement SP when known) minus nothing. Skills are **not** emitted in v1, so a reboot re-locks skills and refunds their SP. This is consistent and never negative. v2 (once §6 taps work): mirror the client value read on the game thread at the 0x17 / 0x24 builders (`client_counters.skill_points`) and emit `skills` |
| currencies | server-owned (grants, codes, freePurchases, missionCredits). Never decreased by the server except through an explicit purchase rule |
| `inventory.loadouts[i]`, `current_loadout` | client (0x16), with the ignore-op0-after-0x22 rule |
| `menu_tutorials`, `sp_difficulty`, `age`/`gender`/`birthdate`/`alias` | client (0x32 / 0xa3 / 0x59 / 0x0b) |
| `progress` | OR-merge: completed nodes are never removed |
| `statistics.sp`, `inventory.weapons` | additive, applied once per de-duplicated 0x11 / 0xac |
| unlocks | `count = max(existing, granted)` (absolute and idempotent); currency adds |

`skills` format (re-checked G:0x89bc60, literal keys): `"skills":[{"skills":[{"name":"<skill>","tier":N}]} …]`. The outer index is the class index; `tier` is the value 0x17 sends. Names come from the §6 skills dump.

`achievements` format (re-checked G:0x898680 / G:0x8985e0): `{"<achName>[<tier+1>]":1, "<achName>_sync":1}`. The tier suffix is used only for multi-tier ids (G:0x898548(id,1)). Names come from the §6 dump.

### 3.4 Validator (run before every send)

- Root is an object.
- Type table as in §2.3.
- Ints within int32.
- No NUL bytes.
- Size within the §2.2 limits.
- Any failure: log, send no profile (fall back to the first-run path), keep the files.

### 3.5 Once-per-profile code bookkeeping

- `state.redeemed` is keyed by the **normalized full code**, suffix included (`UNLOCKALL`, `UNLOCKALL2`).
- It lives in state.json, never inside the client profile.
- Codes are entered in the session and recorded before the push.

---

## 4 Unlock codes, MCVS-style

### 4.1 Entry point

- Main menu → Settings → bottom row **Redeem**. `BOTTOM_BUTTONS_MM=['termsOfUse','about','help','redeem']` (e042 m592852), no flag. It opens RedeemCodePopup; the SWF trims the code (does not upper-case it), closes the popup, then dispatches `SWF_SEND_REDEEM_CODE`.
- Native side: 0x9621c8 → 0xc0e600 stamps `now()` into +0x138 and sends **`53 LL LL | str code`**. Example: `53 00 0e 00 09 'UNLOCKALL'`.
- If the send fails, the client shows INVALID plus message 0x42fe9.

### 4.2 Codes (case-insensitive; server trims and upper-cases; `^([A-Z]+?)([2-9]|[1-9][0-9]+)?$`; base + suffix N≥2 redeems again)

| Code | Grants (in this order, prerequisites first) |
|---|---|
| `UNLOCKALL` | classes → weapons → attachments → camos → gear |
| `UNLOCKCLASSES` | class items (`skill_class`) |
| `UNLOCKWEAPONS` | classes, then weapons |
| `UNLOCKATTACHMENTS` | weapons, then attachments (`<weapon>#<att>`) |
| `UNLOCKCAMOS` | `camo`, `body_camo` items |
| `UNLOCKGEAR` | `<x>_bodyset`, `body_arms/legs/torso`, `mask`, `trinket`, `killsig` items |
| `UNLOCKCURRENCY` | `diamond_dust += economy.codeCredits` (UI credits, default 1,000,000) and `credits += economy.codeGold` (UI gold, default 100,000); capped at 2,000,000,000 |
| custom (`redeem.codes`) | `{"MYCODE":{"items":{"name":count},"credits":n,"gold":n}}` |

- Not in v1: cores (`<core>_l<n>` are core levels 1..5), weapon upgrades (`_inventory_shadow.upd_<weapon>` is loaded only by 0x03, and the max levels are unmapped), paid or unreleased equivalents.
- Unknown code, already-used code or `redeem.enabled=false` → **`54 00 09 00 04 6e756c6c`** (`null` → RedeemResultInvalidPopup; safe, no catalog access).

### 4.3 Delivery on a valid 0x53

1. Resolve the item list from the **item universe** (§4.4). Remove items already owned at ≥ the target count. Record the ledger and inventory, then save.
2. Live path (`unlocks.live`, default true; only when `!in_mission`): send 0x46 batches. Each batch has ≤ `unlocks.batchSize` (400) keys, raw ≤ 1 MB and clen ≤ 65,512 (the frame must stay ≤ 65,535). Batches go out in prerequisite order with `unlocks.batchDelayMs` (250 ms) between them, F1=F2=F3=F4=0.
3. Feedback, which must arrive within 8 s of the 0x53 (0x79a490 checks `now-[+0x138] ≥ 0x1f41`):
   - Send **one object**, never an array (an array fires SUCCESS once per element; an empty array fires nothing): `54 LL LL | str {"shop_name":"<item>","qty":1}`.
   - Send it **only if `<item>` is a granted name present in the live catalog dump** (`dumps/catalog.json`). RedeemRewardPopup 0x9624e8 dereferences `0x5d5198(cfg, FNV(shop_name))` with no NULL check (0x9627dc → 0x9627f4/0x962804).
   - Otherwise send no 0x54. Items still appear and there is no hang (`redeem.popup`: `"auto"` | `"none"`).
4. The next login's 0x03/0x27 carries everything anyway. If live pushes are disabled or fail, the grant applies after a restart.

`unlockAll: true` performs the UNLOCKALL set once (`state.unlockAllDone`). It runs only after the profile has been received (0x74) or the first 0x34/0x24 in the menu, plus `unlocks.startDelaySeconds` (10). Never during the first-load race, and never while `in_mission`.

### 4.4 Item-id source at runtime (no shipped data)

The hook lib builds `dumps/*.json` from the player's own in-memory game data. The sources are given below; the layouts are to be confirmed by the §6 dumps before enabling codes.

- **Catalog** (needs the §2.2 config): cfg = `*(*(base+0x1b9b0c8))`. Entries are inline, sorted, stride 0x60, at `[cfg+0x18, cfg+0x20)`:
  - `+0x0` u32 FNV hash;
  - `+0x8` libc++ `std::string` name (short form: byte0&1 == 0, chars at +1; long form: len at +8, ptr at +0x10);
  - `+0x4c` u32 type hash; compare with FNV of `weapon_bp`, `attachment`, `camo`, `body_camo`, `skill_class`, `mask`, `trinket`, `killsig`, `body_arms`, `body_legs`, `body_torso`, `core`, `unlock_weapons`, `upgrade_skills`.
  - Layout from item-create G:0x710e90. The armory-derived `%s_bp`, `%s#%s`, `%s_bodyset` and `%s_l%d` entries are generated by 0x60f640 inside 0x607270; whether they appear with an empty `_credits` is an unknown.
- **Armory**: armory = `*(*(base+0x1b9ae90))` (0x4e5f98).
  - Weapon names: `vector<std::string>` at armory+0x190 (getter 0x78f260 `ldr x8,[x0,#0x190]; smaddl …#0x18`).
  - Attachment names: armory+0x1a8 (0x7ed020).
  - Count = (end at +8 − begin)/0x18; the vector end is assumed and confirmed by dump.
  - Weapon ownership = armory flag or `count(FNV(name)) > 0` (0x5d5d70/0x5d5e40). Weapons need no catalog.
- **Classes**: the 11 literals at 0x843160: recon, heavy, assault, sniper, support, mercenary, sapper, morph, paladin, enforcer, tracker. These are used as item names only if they are also catalog `skill_class` entries, otherwise logged.
- **Attachment pairs**: only from catalog `attachment` entries. All weapon×attachment pairs are never synthesized.
- Standalone desktop host (no hook): only currency codes work; the rest reply `null` and log "no item universe".

### 4.5 Config flags (`settings.json`)

The MCVS equivalent is given where one exists.

```json
{"redeem":{"enabled":true,"codes":{},"popup":"auto"},
 "unlockAll":false,
 "unlocks":{"batchSize":400,"batchDelayMs":250,"startDelaySeconds":10,"live":true},
 "economy":{"xpMultiplier":1.0,"spMultiplier":1.0,"startCredits":0,"startGold":0,
            "codeCredits":1000000,"codeGold":100000,"missionCredits":0,"freePurchases":false},
 "profile":{"send":true,"mirrorClientCounters":false},
 "bald":{"serve":true},
 "patches":{"levelUpRewardsGuard":true}}
```

- `redeem.enabled` = `assets.couponsEnabled`; also accept that alias.
- `redeem.codes` = `assets.coupons`.
- `unlockAll` and `unlocks.*` = the same names.
- `economy.*` = MCVS multipliers.

### 4.6 Risks specific to codes

- The popup NULL dereference (mitigated by catalog gating).
- SetCount inserts any non-zero hash, so bogus names may confuse later UI (mitigated by universe-only names).
- The flag-1 badge pass 0x6204a8 has not been tested on huge batches (mitigated by batching).
- A 0x46 arriving during a purchase clears the lock.
- Level-up popups inside 0x5f58e8 need the §2.2 config or the §5 guard patch.

---

## 5 Change list

### server/

| File | Change |
|---|---|
| `core/lz4.hpp` (new) | Own greedy LZ4 **block** compressor (4-byte hash table, 64 KB window, last 5 bytes as literals) plus the existing `lz4_store`. Unit round-trip test against our own decoder |
| `core/store.hpp/.cpp` (new) | Atomic JSON file I/O (§3.2), `.bak`/`.broken` handling |
| `core/settings.hpp/.cpp` (new) | Load or create `settings.json` with §4.5 defaults; env overrides (`MC5_TS_PROFILE=0/1`) |
| `services/services.hpp` | `ServerContext`: `std::string data_dir`, `Settings settings`, `std::unique_ptr<ProfileStore> profile`, `ItemUniverse universe` (mutex, filled by the host), `std::function<bool(const std::string&)> push_ts` (live meta writer, set/cleared by MetaConn), `anubis.gate5a`, `anubis.profile_sent`, `last_redeem` for `/_mc5/status` |
| `services/ts_codec.hpp` (new) | Move `BeReader`, `ts_frame`, `blob32`, `put_u*` here from meta.cpp; add `f32le`, `str16`, `parse_0x11()` (lenient, boundary-checked), `frame_profile()` (0x03/0x27 choice), `frame_inv_changes()` (0x45/0x46), `fnv1a()` |
| `services/profile.hpp/.cpp` (new) | `ProfileStore`: model, `render()` (§2.3), `validate()` (§3.4), `apply_*` for every §2.1 frame, 0x11 de-dup, `sp_earned`, the redeem ledger, `starter()` (from 0x59/0x0b/country with `economy.start*`) |
| `services/game_config.cpp` (new) | `config_json()` returns `{"game":{"_level_up_rewards":[{}]}}`; validated; the only 0x3e source (empty config is never sent) |
| `services/unlocks.hpp/.cpp` (new) | Code table §4.2, normalize/suffix, group resolution from `ItemUniverse`, batch planner, popup-item choice |
| `services/meta.cpp` | Burst §2.2 (replace `gate_burst()`; remove `default_profile()`); a switch over §2.1 (0x06→0x07, 0x11→0x12, 0x21→0x22, 0x53→§4.3, 0x41/0x42/0x44/0x4d/0x48→0x45, persistence for the rest); "ignore next 0x16 op0" after every S→C 0x22; `in_mission` tracking; deferred unlockAll timer thread; register and clear `ctx.push_ts`; update `ts_name()` (0x16 "loadout", 0x10 "mission-start", 0x11 "mission-end", 0x17 "skill", 0x19 "achievement", 0x1a "notification", 0x32 "menu-tutorials", 0xa3 "difficulty", 0x24 "menu-return", 0x66 "killsig-cond", 0x06 "lvc-request", 0x53 "redeem", 0xac "mission-fail-stats"); log every S→C frame >48 B in full as well |
| `services/asset.cpp` | BALD routes §2.4, registered before `asset_absent` (method "*", name-prefix dispatch inside a single `assets/{clientId}/{name}` handler) |
| `services/misc.cpp` | `/_mc5/status`: profile summary (xp, currencies, nodes, loadouts n, redeemed codes, last 0x11 key, profile_sent, gate5a) |
| `CMakeLists.txt` | add the new sources |
| `tests/` | lz4 round-trip; 0x11 parse of the device prefix plus a synthetic full frame; validator rejects `private_profile:{}`; code normalize (`" unlockall2 "`→`UNLOCKALL2`); BALD bodies and toc JSON; 0x3e frame bytes == §2.2 |

### hosts/embedded/

| File | Change |
|---|---|
| `bootstrap.cpp` | `diag::init` returns the chosen dir (or add `diag::data_dir()`); `ctx->data_dir = dir + "/MC5Offline"`; load settings; create `ProfileStore`; install §6 hooks after libMC5 load (same place as the existing installers) |
| `patch.cpp` / `patch.hpp` | `apply_levelup_rewards_guard()`: `patch_site("levelup-rewards-guard", base+0x628af8, EXPECT, PATCH, 68, true)`. **EXPECT** `3f000071 cd010054 080043f9 eaf301b2 09fc42f9 6a5595f2 eb071d32 080109cb 2b242b9b 08fd4393 087d0a9b 2a7c4093 1f010aeb 6081899a c0035fd6 00fc42f9 c0035fd6`. **PATCH** = same with word0 `09fc42f9` (ldr x9,[x0,#0x5f8]), word1 `c90100b4` (cbz x9,0x628b34), word15 `00e01791` (add x0,x0,#0x5f8): `09fc42f9 c90100b4 080043f9 eaf301b2 09fc42f9 6a5595f2 eb071d32 080109cb 2b242b9b 08fd4393 087d0a9b 2a7c4093 1f010aeb 6081899a c0035fd6 00e01791 c0035fd6`. An empty table now returns &cfg->table ({0,0}); all three callers' `cmp x9,x8; b.eq` skip. Non-empty behaviour is unchanged (negative or 0 index → begin via csel). Ship it together with the config fix |
| `patch.cpp` | §6 trace hooks and dump routines (`install_trace_hook_fp` with 16-byte fingerprints) |
| `diag.cpp` | Cache sweep: delete `hc.dat` if ≤ 4 bytes (the poisoned `{}`); never touch `bald/` |
| `diag_dump.cpp` (new) | §6 dumpers writing `dumps/*.json` and filling `ctx.universe` |

---

## 6 Client diagnostics to add

All hooks are entry traces via `install_trace_hook_fp`. Each prologue below was checked relocatable (no PC-relative instruction in the first 16 bytes); the first 8 bytes are the fingerprint shown, and the full 16 bytes must be compared at install.

| Site | Prologue (first 8 B) | Log / use |
|---|---|---|
| 0x95cb20 stats builder | `e923b96d fc6f01a9` | cfg+0x5f8/+0x600 begin/end (proves the fix), lr |
| 0x4f18a0 profile apply | `ff8304d1 fc7300f9` | arrival; a poller then logs gate+0x5a/+0xb0/+0xb2 flips (apply success) |
| 0x79af60 0x12 apply | `ff4304d1 fc570ea9` | the reply JSON (x1/x2), achMgr+8/+0xa after |
| 0x79a490 0x54 apply | `ffc305d1 fc5714a9` | redeem reply |
| 0x9624e8 RedeemRewardPopup | `e80f19fc fc6f01a9` | global name at 0x1bc0b08 and `0x5d5198` hit/miss (read-only lookup on the game thread) |
| 0x5f58e8 inventory-change job | `fc6fbaa9 fa6701a9` | F1/F3, JSON size |
| 0xc0cae8 (0x17), 0xc0b948 (0x16), 0xc0c2d0 (0x11), 0xc0d250 (0x19), 0xc0e600 (0x53) builders | `fc5fbca9 f65701a9` / `fc0f1bf8 f85f01a9` / `fc6fbaa9 fa6701a9` / `fc5fbca9 f65701a9` / `fc57bda9 f44f01a9` | **counter tap** on the game thread: `pm=*(*(base+0x1b9ae58))` (0x4f1858); `count = 0x5d5600(pm+0x4b8, FNV(name))` for xp, skill_points, skill_points_spent, diamond_dust, credits; hand these to `ctx.client_counters`. At 0x19, also resolve the achievement key via 0x7985e0(achMgr=`*(*(base+0x1b9ae70))`, &std::string, id, tier) |
| 0x8efb50 top-bar builder (verify relocatable at install) | — | call count/timing (resolves the -1 question) |

Dumps, run once per launch on the game thread from the first 0x24/0x34-adjacent builder tap after config b3 (never from our server thread):
- `ks.json`: vector at base+0x1bbefa0 of 16-byte entries {u32 hash @+0, `char*` @+8} (0x83a710/0x83a798). Proves the literal key names (age, gender, alias, birthdate, male/female, …).
- `catalog.json` (§4.4 layout): hash, name, type-hash and type name if matched.
- `armory.json`: weapon and attachment name vectors with counts, and FNV of each.
- `achievements.json`: achMgr+0x108 table (0x6e1a48 → begin; entry 0x30, `std::string` name @+0, SP reward int @+0x2c), plus multi-tier flag via 0x798548.
- `skills.json`: skills object (G:0x7a13c0 context) +0x10 → class entries stride 0x78, +0x40 vector of 0x18-byte {skillDef* @+0, tier @+8}. Hex-dump the first 0x60 B of each skillDef until the name/cost offsets are known.

Logging:
- The existing `log_full_payload` (>48 B) covers C→S. Add the same for S→C (burst, profile, 0x12, 0x45/0x46, 0x54), with length plus FNV of the payload.
- Write the TS trace to `<files>/MC5Offline/ts-trace.log` (rotating 4 MB) so a device round captures the full 0x11 and 0x16 without logcat truncation.
- BALD: log every `bald_*` GET with Range and status.

---

## 7 Risks and unknowns (ranked)

1. **The first-ever 0x03/0x27 apply is untested on device.** Loader type traps (wrong container type gives a jsoncpp assert). Mitigation: validator; first run sends none; `profile.send` kill-switch.
2. **Config tail with `"game"` runs for the first time**: 0x607270 sub-parsers (_credits/_offers/…), 0x614e48, 0x614fb8, 0x4fc6d0, 0x50f158, 0x4e46a0→0xc19608, promotion/ads, 0x5e8f98. These were audited only for null-safe lookups. Mitigation: the 0x628af8 guard patch ships with it.
3. **Currency -1 may persist.** The native sc/hc feed is unidentified (§1.3). Mitigation: §6 top-bar tap; the criterion is the next device round.
4. **Item-universe layouts** (armory +0x190/+0x1a8 vector ends, catalog entry +0x8/+0x4c, whether 0x60f640 generates `#att`/`_bp` without `_credits`). Codes stay off for non-currency groups until `dumps/` confirm them.
5. **Gender** is compared against ks("male")/ks("female"). If ks maps them to obfuscated strings, gender reads as 0. Resolved by `ks.json`.
6. **0x46 on uncatalogued names**, the badge pass and very large batches are untested (the MCVS `UnlockMerc_ALL_MAX` lesson). Batch them, prerequisites first.
7. **Skills and achievements persistence** needs names (§6). v1 refunds SP and re-locks skills on reboot; achievements re-unlock and the client re-grants their SP locally until the next login overrides it.
8. **Purchase replies**: F1/F3 meaning for 0x41/0x42 and the price source are unmapped. The v1 error reply blocks the shop.
9. **statistics placement** (`sp` vs `general`) for 0x11/0xac stats; may show wrong totals on the Profile screen.
10. **Level-up rewards and mission credits**: possibly server-driven (`_pending_inv.levelup`, F1=`endmission_rwd_sp`). Not implemented; `missionCredits` is opt-in.
11. 0x11 str2/blob loss mid-frame (writer overflow) leads to under-counted XP for very large missions.
12. BALD: an online-era `bald/` folder would be pruned by the new toc (fresh installs have none); 200 vs 206 is believed equivalent for one chunk; about 1 MB free disk required.
13. The LZ4 compressor is new code. Round-trip unit tests are mandatory.
14. The current user's device has no stored server state. The first run on the new build repeats the age gate and tutorial once; there is no migration.

---

## 8 Disagreements table

| # | Topic | Position A | Position B | Settled | Basis |
|---|---|---|---|---|---|
| 1 | 0x3e bytes for `{"game":{"_level_up_rewards":[{}]}}` | len 0x2e, n 0x27 | len 0x2a, n 0x23 | **0x2a / 0x23** (JSON 35 B) | recomputed |
| 2 | Minimal config | `_level_up_rewards:[{}]` / `[]` | `{"game":{}}` | all valid; if present it must be an array | 0x614c78 resize(size+1); index()=−1 for object members |
| 3 | Crash cause | missing profile | `{}` config | **config** | 0x607388 exit → NULL at 0x628af8 [re-checked] |
| 4 | Level-up popups 0x941738/0xa3e820 | local level-up natives | config job 3 from 0x45/0x46 | **job 3** | BL callers only in 0x5f58e8 |
| 5 | Why the outcome screen hung | missing post-mission 0x22 | missing 0x12 | **0x12** | 0x80effc..0x80f00c wait on achMgr+8 [re-checked] |
| 6 | Post-mission b2 clear | always | MP-only | **MP-only** | 0x4ed160 = `ldrb [x0,#0xc4]`; the same flag routes 0x19 to GS 0xbf2570; device 0x19 arrived over TS [re-checked] |
| 7 | When to send the profile | after the burst and after each mission | login only, gate5a=1, before 0x04 | **login only** | a load resets age/gender/inventory (0x5dffd8, 0x5ce9a8) |
| 8 | 0x16 fields | slot/flags unknown | mode, loadout idx | **mode, idx** | builder 0xc0b948 |
| 9 | 0x10 meaning | completion | start | **start** | only caller G:0x88e538; completion is 0x11 |
| 10 | 0x17 cost | server `skill_points -= cost` | no cost; byte 3 = tier | **tier, no cost** | 0x7a1338 writes table[c*0x78+0x40][s*0x18+8], read back as `tier` by G:0x89bc60 [re-checked] |
| 11 | Skills profile keys | hashed/unknown | — | **literal** `skills`/`name`/`tier` | G:0x89bc60 [re-checked] |
| 12 | Achievements profile format | `achievements[tier][id]=1` | — | **`{"<name>[tier+1]":1,"<name>_sync":1}`** | G:0x898680, G:0x8985e0 [re-checked] |
| 13 | 0x45/0x46 header | u32, u64?, u32, u32 | u32 BE, f32 LE, u32 BE, u32 BE | **u32, f32 LE, u32, u32** | decomp case 'E'/'F' (9cf5a0, 9cf858, 9cf5a0, 9cf5a0) [re-checked] |
| 14 | F1 | gift boolean | reason hash | **reason hash; 0 = silent** | 0x5f58e8 comparisons |
| 15 | 0x54 shape | object or array | single object | **single object; `null` for invalid** | array fires SUCCESS per element |
| 16 | No 0x54 → hang? | possible | no hang | **no hang** | SWF hides the popup before dispatch |
| 17 | -1 currency | empty catalog (rd_currency) | SWF placeholder | **placeholder; feed unidentified** | e047 m581296; 0x5d5600 returns 0 |
| 18 | Weapons need catalog | yes | armory + count | **armory + count**; catalog needed for popup/shop/badges | 0x5d5d70/0x5d5e40 |
| 19 | `%s_l%d` | skill levels | core items | **core** | type hash("core") in G:0x70f640 |
| 20 | `event_*` keys | top level | inside `tournaments_sem[]` | **inside** | G:0x6e1498 l.472-500 |
| 21 | Redeem transport | MCVS `GET coupons/{cid}/{code}` | TS 0x53/0x54 | **TS** | `/coupons/` has no xref; 0xc0e600 |
| 22 | Grant transport | new 0x03 | 0x45/0x46 | **0x46 live, 0x03 at next login** | 0x03 resets inventory |
| 23 | `battlepack` cheat | server purchase | local SetCount | **local** | 0x8ed34c |
| 24 | 0x5f52d0 → 0x607270 | only if iap.prices empty | also non-empty and valid | **both; never send iap** | 0xc6f788 path |
| 25 | Overflow loss | trailing fields only | mid-frame possible | **mid-frame** | writers never consult +0x19 |
| 26 | 0x27 helps size | yes (existing lz4blob) | — | **only with a real compressor** | `lz4_store` is literal-only |
| 27 | BALD suffix builder | G:0xc619d8 | caller G:0xc61858 | **G:0xc61858** | decomp |
| 28 | BALD retry period | 20 ms + RTT | 20 + 1 ms + RTT | **21 ms + RTT** | outer worker loop G:0x1373960 |
| 29 | BALD hook-off permanent | yes | undone by resume G:0xc62348→G:0x136ded0 | **not permanent; serve the 3 assets instead** | decomp |
| 30 | bald dir1 == dir2 | inferred | identical code | **same folder** | G:0xc92628 ≡ G:0xc63e38 |
| 31 | Existing `default_profile()` | "structural keys" | crashes (`private_profile:{}`), wrong keys | **remove** | asBool 0x1153c28 |

---

## 9 What is implemented (M2, commits 712f76b..)

| Area | Implementation | Differences from the spec above |
|---|---|---|
| TCP_Config | `config_json()` = `{"game":{"_level_up_rewards":[{}]}}` in the login burst (`settings config.sendGame`) | none |
| Guard patch | `apply_levelup_rewards_guard()` (patches.md #5) | none |
| Save | `Progress` (`server/services/profile.*`), `<files>/MC5Offline/{settings,profile,state}.json`, atomic + `.bak` + `.broken-*` | loadouts are kept in `state.json` and merged at render |
| Login profile | 0x03 ≤ 65,528 B, else 0x27 with our own LZ4 (hash-chain matcher; ~12× on item JSON) | adds a **crash guard**: armed on send, confirmed by 0x10/0x24 or 20 s alive; two unconfirmed launches disable it |
| Frames | 0x59, 0x0b, 0x10/0x2d, 0x11→0x12, 0xac, 0x24, 0x16 (op0-after-0x22 ignored), 0x17, 0x19, 0x1a, 0x32, 0xa3, 0x06→0x07, 0x21/0x96→0x22 | purchases (0x41…) are logged, not answered (`economy.purchases:"none"`); `missionCredits` not implemented |
| 0x12 | `{"xp":X,"sp":Y}`, sent on every 0x11, applied to the save once per distinct payload | X = xp.rewards + xp.medals + xp.objectives, Y = sp.value (flat dotted keys or nested); to be confirmed by the device 0x11 dump |
| BALD | index `1`, toc_1, `<dlc/>` map (`settings bald.serve`) | adds the "bald" crash guard (60 s) |
| Codes | 0x53 → 0x45/0x46 grants (≤ 400 keys, currencies in their own frame) + 0x54 only for catalog items; `null` for invalid | adds `UNLOCKKILLSIGS`; a code whose item list is missing is reported invalid and **not consumed** |
| Item lists | `hosts/embedded/item_dump.*` on the 0x53 / 0x16 builder hooks (game thread) | §10 |

### 9.1 Findings of the second verification round (wf `mc5-unlock-preconditions`)

- **Push safety (confirmed twice).** With F1 = 0, 0x5f58e8 takes the explicit branch `0x5f5bc8 cbz w26`. That branch zeroes every popup flag, so the level-up popups, `0x5e8f98` and the unchecked catalog sites cannot run. The only catalog lookups left are NULL-checked. With an empty catalog, a push is a plain SetCount per key and raises no "new" badges.
- **Same-frame duplicates.** SetCount (`0x5cf5d0`, w3 = 0) appends new nodes unsorted but binary-searches the whole vector until the frame's final sort. An existing key processed after an append can therefore be inserted twice. Currencies always exist on the client, so they get their own frame.
- **Ownership (confirmed).** Ownership is a count > 0 of FNV(name) (`0x5d5e40`). It does not depend on the catalog:
  - class = item named after the skills.bin class (`0x5e5c90`; free when unlockLevel == 1);
  - weapon = base name (`0x5d0d30`; free when attribute 0xf508ab3c is missing or > 0.1);
  - attachment = `<base>#<att>` (`0x5d6a18`);
  - camo = `0x5d5d70`;
  - trinket = `0x5d62c0`;
  - mask = `0x5d7300`;
  - body piece = `0x5d7530`;
  - bodyset = all pieces owned (`0x5d7580`);
  - killsig = `0x5db888`.
- **Weapon count must be exactly 1** (or 1 + PRO-list length). The resolver `0x5d5370` reverts to the base weapon for anything larger. The server grants 1.
- **Never push xp** through 0x45/0x46: XP arrives through 0x12, and the login profile carries it.
- **0x12** (`0x79af60` → apply `0x79a0e8`) reads `error`, `xp`, `sp`, `cup`/`solo`.
  - Any non-null `error` shows popupProgressNotSaved.
  - `xp` and `sp` are added by the client itself. Level-ups come from the local rewards.bin "XP" table and never touch `cfg+0x5f8`.
  - On success, the pending achievements unlock locally: 0x19 is sent and their SP is added on the client. The server does not yet know those SP amounts (§7 risk 7).
- **0x07 u32 0** (`0x831cb8`, `strh 0x0001 → ts+0x70`) is the same path as the loader's 15 s timeout (`0x82fb04`). The level then loads from the local packs (`LoadRawLvl 0x5c33b0`).
- **0x54 `null`** gives INVALID (`0x9622f0`) with no catalog access. With no 0x54 there is no spinner: the SWF hid the popup before sending.

## 10 In-memory item lists (no shipped data)

All addresses are ELF vaddrs (libMC5 6.0.12a). Each list is self-checked: the hash stored next to every name must equal FNV-1a(name), or the whole list is dropped.

**Armory.** A = `*(base+0x1bbed40)` (getter `0x4e5f98`). It is allocated and parsed synchronously at boot (`0x4e5c10`), before StartLogin.

| List | Layout (offsets from A) | Granted |
|---|---|---|
| weapons | names vector `+0x190` (base first, then PRO variants), count of base `+0xc8`, hashes `+0xd0`, records `+0xe8` / 0x118 | base weapons |
| attachments | records `+0x118` / 0x78, names `+0x1a8`, hashes `+0x100`; WM rows `+0x160` / 0x18 of {u32 att, i32 v1, i32 v2} | `<w>#<a>` for the first triple per att with v1 > 0 (the game's catalog rule, `0x60f640`/`0x7eaa68`) |
| camos | records `+0x288` / 0x70 (hash +0, free flag +0x4c bit 0), names `+0x2a0` | non-free |
| masks | records `+0x258` / 0x90, names `+0x270` | all |
| trinkets | records `+0x2f8` / 0x40 (free when +0x2c != 0), names `+0x310` | non-free |
| body pieces / body camos | `+0x18` / 0x90 and `+0x0` / 0x98; name string at +0x10, hash +8; default +0x39, hidden +0x40 | non-default, non-hidden |

**Killsigs.** Manager M = `*(base+0x1bbed00)`:
- count `M+0x1a8`, array `M+0x1b0`, stride 0x50;
- each entry: name +0, item hash +0x18, condition +0x20;
- granted when the condition is not "none".

**Classes.** Skills manager S = `*(base+0x1bbed08)`:
- SKILL_TREE vector at `S+0x10`, stride 0x78;
- each entry: hash +0, name +8, unlockLevel +0x28;
- granted when unlockLevel != 1.

The 11 literals at `0x843160` are the fallback; they map hashes to UI strings, so the spelling is only medium-confidence.

**Not granted:**
- PRO variants;
- cores (`<core>_l<n>` levels);
- grenades (gated by level, not by the inventory);
- `<set>_bodyset` (the pieces are granted instead);
- event boosters.
