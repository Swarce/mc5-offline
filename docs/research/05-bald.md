# 05 — BALD: using the player's own restored DLC offline

The campaign zones (z2_downtown, z3_venice, z4_construction, z5_blackwater), the MP maps (z0_mp), vehicles and the
outro video are runtime DLC handled by Gameloft's BALD manager under `<files>/bald/`. This reference was
reverse-engineered by the `mc5-bald-local-mirror` workflow (on-disk layout, server replies, DLC wrapper), with each
area adversarially verified. **§0 says what is implemented**; the spec that follows is the research behind it.

## 0 Implemented (commit b63b2a8)

* `server/services/bald_mirror.*` runs a read-only preflight (gates H1..H10 below). On a full pass, the index request
  `bald_<n>___index` gets **200 with the exact bytes of the player's `bald___index___.txt`**. BALD then
  byte-compares the body (state 1), accepts the local toc, hashes and files by existence, and is ready. No other
  request follows.
* **Toc and payload requests are never answered** (held 404). A served toc sends BALD to state 2. State 2 erases
  every local asset missing from that toc (G:0x1370880) and rewrites the bookkeeping files.
* The old `bald.serve` path (index "1", a one-asset toc, an empty map) is **removed**: it crashed the menu
  (research/02 §20) and, with a real folder present, would have erased it.
* `settings.json` `bald`: `mode` = `"mirror"` (default) or `"off"`; `holdMs` (2000) for every 404;
  `requireSizes` (true) enforces H10. `settingsVersion` 3 drops bald defaults written by v1/v2.
* The boot sweep (`diag::remove_offline_bald_cache`) deletes only individual marker files from earlier offline
  builds. It never deletes a directory or any other file.
* Crash guard "bald": armed on each served index, confirmed after 60 s alive; two unconfirmed launches switch the
  mirror off.
* Not implemented (by design): serving payload ranges, md5 verification, an import directory. A missing asset leaves
  its zone "not downloaded"; the preflight logs which file is missing.
* Verified offline against the player's real `bald___{index,version,toc,hashes}___.txt` with sparse payload files:
  52/52 assets and 5 locations pass. The map file itself (3,018 B) was not available, so H9 runs for the first time
  on the device. If it fails, the log prints the map's tag structure and the safe 404 stays.

---


Addresses are Ghidra (G) unless marked ELF. G = ELF + 0x100000. Anything not confirmed by both an investigation and its verifier is marked **[INFERENCE]**. The spec covers:
- `server/services/asset.cpp`: the BALD reply logic.
- `server/services/profile.cpp`: the `settings.json` schema and its migration.
- `hosts/embedded/bootstrap.cpp` and `hosts/embedded/diag.cpp`: telling the server where the files are, and making the boot sweep safe.

## 0. Root cause and the fix in one paragraph

The game ignores the restored folder because BALD never reads its local bookkeeping until one index GET succeeds:
- State 1 (G:0x136e370) substate 1 returns early until the index task reaches `task+4 == 3` (ELF 0x126e3c4 `bl 0x8e1728`; 0x8e1728 is `ldr w8,[x0,#4]; cmp w8,#3; cset eq`).
- Only the worker's success branch writes that value (G:0x1373a00 case 1, after GetAsset G:0xd8d810 returns 0).
- Our held 404 never succeeds, so BALD loops in state 1.
- The wrapper's ready test G:0xc929b0 (`ldr w8,[x0,#0x70]; cmp w8,#2; cset gt`) stays false, wrapper tick G:0xc61e28 case 0 never runs, and every campaign zone and MP map shows as not downloaded.

The fix has two parts:
- **Index:** answer `GET assets/<clientId>/bald_android_astc_h___index` with 200 and the exact bytes of the player's own `bald___index___.txt` ("244"). BALD then byte-compares that body with the local file, parses the local toc and hashes, marks every existing file as downloaded, and enters state 3 (ready). No toc request, no asset request and no file deletion follow.
- **Everything else:** keep the toc at 404 forever. Serve a Range for an asset only when a verified local copy exists.

## 1. Where the files are

| Item | Value | Status |
|---|---|---|
| BALD dir | `<base>/bald/`, built by G:0xc63e38 == G:0xc92628 as `FUN_005be028()` + `"bald/"` (string 0x16c97d2). It mkdirs the folder if missing. The dir string already ends in `/`. | verified |
| `<base>` | `/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/` | **[INFERENCE]**, strong (see below) |
| Asset payload | `<bald dir><full toc asset name>`: no extension, no per-chunk files. Example: `.../files/bald/bald_android_astc_h_z3_venice_gla2_2` | verified (G:0x136feb0 exists check ELF 0x12707a0; worker rename ELF 0x12743bc) |
| Partial download | `<bald dir>temp_<full name>`. It is preallocated to `file_size`, never mounted, and resumed by per-chunk md5. | verified (G:0x1371140) |
| Bookkeeping | `bald___index___.txt`, `bald___version___.txt`, `bald___hashes___.txt`, `bald___toc___.txt`, each with a `temp_` twin used only during a state-2 rewrite | verified (G:0x136d4a8; .bss 0x1d3b518..0x1d3b5c0) |

Why `<base>` is probably /sdcard:
- The 13:50 device log's `rm_caches_in` walk lists `/sdcard/.../files/bald`.
- The same walk covers `/data/data/<pkg>/files` and `/data/user/0/<pkg>/files` with no `bald` subdirectory.
- G:0xc63e38 mkdirs its dir when it is missing, so if the internal path were BALD's base, a `bald/` folder would exist there after any earlier launch.

The server must still probe both locations and log which one it uses (§3.1).

## 2. Exact names the player's folder must hold

All of these go directly in `<base>/bald/`. The sizes come from the player's `bald___hashes___.txt`. The total is 832,976,516 B, and every chunk_size is 2097152.

Bookkeeping files:
```
bald___index___.txt      3 B   "244"  (bytes 32 34 34, no newline/BOM)
bald___version___.txt    7 B   "6.0.12a"
bald___toc___.txt        2892 B  {"_hash":"6360da99…","_version":"6.0.12a","assets":[52 × {"name":…}]}\n
bald___hashes___.txt     121072 B  [318 × {"chunk_size":2097152,"file_size":N,"hashes":[…],"name":"…"}]\n
```

Payload files, as name and byte size. The 11 `z0_mp_*` files are MP location `z0_mp`.

```
bald_android_astc_h_map_android_dlc_97            3018
bald_android_astc_h_vehicles_dlc_gla2_1           3752065
bald_android_astc_h_vehicles_dlc_ktx_gla2_0       4648257
bald_android_astc_h_vehicles_dlc_lvl_gla2_0       28932
bald_android_astc_h_vehicles_dlc_stream_gla2_1    511400
bald_android_astc_h_video_outro_dlc_gla2_0        17881566
bald_android_astc_h_z0_mp_gla2_7                  27584233
bald_android_astc_h_z0_mp_irr_gla2_2              10659186
bald_android_astc_h_z0_mp_ktx_gla2_18             32318876
bald_android_astc_h_z0_mp_ktx_part1_gla2_29       31855936
bald_android_astc_h_z0_mp_ktx_part2_gla2_36       14112111
bald_android_astc_h_z0_mp_lvl_gla2_80             13131228
bald_android_astc_h_z0_mp_part1_gla2_4            31471421
bald_android_astc_h_z0_mp_part2_gla2_43           31360103
bald_android_astc_h_z0_mp_part3_gla2_51           29114888
bald_android_astc_h_z0_mp_part4_gla2_42           26140600
bald_android_astc_h_z0_mp_snd_gla2_1              10782176
bald_android_astc_h_z2_downtown_gla2_2            24989021
bald_android_astc_h_z2_downtown_irr_gla2_0        3150328
bald_android_astc_h_z2_downtown_ktx_gla2_2        23770410
bald_android_astc_h_z2_downtown_lvl_gla2_10       9195719
bald_android_astc_h_z2_downtown_part1_gla2_2      24773784
bald_android_astc_h_z2_downtown_part2_gla2_1      24890556
bald_android_astc_h_z2_downtown_part3_gla2_1      24443075
bald_android_astc_h_z2_downtown_part4_gla2_0      4405124
bald_android_astc_h_z2_downtown_snd_gla2_1        29134387
bald_android_astc_h_z2_downtown_snd_part1_gla2_1  1409832
bald_android_astc_h_z2_downtown_stream_gla2_2     39824672
bald_android_astc_h_z3_venice_gla2_2              22792874
bald_android_astc_h_z3_venice_irr_gla2_0          1594891
bald_android_astc_h_z3_venice_ktx_gla2_0          11539200
bald_android_astc_h_z3_venice_lvl_gla2_8          4292879
bald_android_astc_h_z3_venice_part1_gla2_1        25677673
bald_android_astc_h_z3_venice_part2_gla2_2        26527089
bald_android_astc_h_z3_venice_part3_gla2_2        17634301
bald_android_astc_h_z3_venice_snd_gla2_1          25065492
bald_android_astc_h_z3_venice_stream_gla2_2       23022972
bald_android_astc_h_z4_construction_gla2_2        23781830
bald_android_astc_h_z4_construction_irr_gla2_0    3592275
bald_android_astc_h_z4_construction_ktx_gla2_2    10539814
bald_android_astc_h_z4_construction_lvl_gla2_2    4030024
bald_android_astc_h_z4_construction_part1_gla2_1  20543950
bald_android_astc_h_z4_construction_part2_gla2_1  7113214
bald_android_astc_h_z4_construction_snd_gla2_1    18276006
bald_android_astc_h_z4_construction_stream_gla2_1 6079066
bald_android_astc_h_z5_blackwater_gla2_1          24218110
bald_android_astc_h_z5_blackwater_irr_gla2_0      2874038
bald_android_astc_h_z5_blackwater_ktx_gla2_0      8591279
bald_android_astc_h_z5_blackwater_lvl_gla2_1      1636922
bald_android_astc_h_z5_blackwater_part1_gla2_2    17940457
bald_android_astc_h_z5_blackwater_snd_gla2_1      20686350
bald_android_astc_h_z5_blackwater_stream_gla2_2   9582906
```

Files that do not count:
- `*.gla2`, `*.dat` or other extensions.
- Files in sub-folders.
- Names with a different `_<rev>` suffix.
- `temp_*` files.

BALD treats all of these as missing (there is no directory scan anywhere in BALD).

How names map to lookup keys (G:0x136feb0, stored at entry+0x20). The key is `name.substr(len("bald_"+n+"_"), name.rfind('_') - len(...))`. For example, `bald_android_astc_h_z0_mp_ktx_part1_gla2_29` becomes the key `z0_mp_ktx_part1_gla2`. Lookup G:0x136e010 lowercases the requested name and maps `.` to `_`:
- The wrapper requests `map_android.dlc`, which becomes `map_android_dlc`.
- For a map pack `P` the wrapper requests `P.gla2` (G:0xc629a8), which becomes `p_gla2`.

## 3. Server design

### 3.1 Inputs and plumbing

- `ServerContext` (server/services/services.hpp) gets new fields:
  - `std::vector<std::string> bald_dir_candidates`;
  - `std::string bald_dir` (resolved; empty means none);
  - `BaldMirror bald` (state, below).
- `hosts/embedded/bootstrap.cpp` fills the candidates before `register_services`, in this order:
  1. `settings.bald.dir` if non-empty;
  2. `<external files dir>/bald/`, the dir that already receives `mc5offline.log`;
  3. `/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/bald/`;
  4. `/data/data/<pkg>/files/bald/`;
  5. `/data/user/0/<pkg>/files/bald/`.
- Resolution: the first candidate that contains a regular file `bald___index___.txt` wins. Log every candidate together with its result.
- **All access to that dir is read-only.** Use `open(O_RDONLY|O_CLOEXEC)`, `fstat` and `pread` only. No `fopen("w")`, `unlink`, `rename`, `mkdir` or `utime` may touch a path under any candidate. Enforce this in code review with a grep (§6.6).

### 3.2 `settings.json` (profile.cpp)

Bump `kSettingsVersion` to 3 and change the `bald` default to:

```json
"bald": {
  "mode": "mirror",
  "holdMs": 2000,
  "dir": "",
  "requireSizes": true,
  "verifyMd5": "off",
  "importDir": "",
  "serveRanges": true
}
```

- `mode` is `"mirror"` (the default) or `"off"`, which means always the held 404, exactly as today.
- `verifyMd5` is `"off"`, `"log"` or `"strict"`.
- `importDir` is empty or a path to a read-only folder holding missing payloads, named exactly as in the toc.

Migration from v2 to v3:
- Drop `bald.serve`, whatever its value.
- If it was `true`, log `[progress] bald.serve=true is retired (it would erase the real DLC); using bald.mode=mirror`.
- No setting can re-enable the old reply set.

### 3.3 Remove the old replies

Delete these from asset.cpp:
- `bald_asset()`'s `"1"` reply;
- the `__toc_1` reply;
- the `"<dlc/>"` reply;
- the `guard_allowed("bald")` → `bald_asset` branch.

Why: index "1" differs from the local "244", so state 1 goes to state 2. State 2 then downloads `__toc_1`, and G:0x1370880(this, **0**, newToc, oldToc) erases `<dir><name>` and `<dir>temp_<name>` for all 52 assets:
- the diff call is at ELF 0x126edac/0x126edb0;
- the erase calls are at ELF 0x1270e44 and 0x1270fc0.

This happens before the temp_ writes and the space checks, and it then overwrites all four bookkeeping files. Keep `bald_name()`, which recognises the `android_{astc,etc}_{h,l}` prefixes.

### 3.4 Preflight (`BaldMirror::preflight`, run once per process before the first BALD reply)

It reads the resolved dir and computes `ok_index` (bool), `index_bytes`, the asset table and a list of reasons. The results are cached for the process, with no re-reads, so every reply in a session is identical.

**Hard gates.** Any failure makes `ok_index=false`, and the server keeps the held 404, which is safe (§5). Each gate prevents a mismatch path or a crash:

| # | Check | Why (address) |
|---|---|---|
| H1 | `bald___version___.txt` is exactly the 7 bytes `6.0.12a` | Otherwise state 1 → state 2, and +0x139=1 arms the md5 delete (ELF 0x126e628, 0x126e7b0) |
| H2 | `bald___index___.txt` is 1 to 64 bytes and contains no `\r`, `\n`, space or BOM. Use its bytes verbatim; do not trim them. | Byte compare against the reply body (ELF 0x126e868-0x126e8e4); an empty body also falls into state 2 |
| H3 | `bald___toc___.txt` is non-empty, parses as a JSON object, has `_version` == `"6.0.12a"`, and has `assets` as a non-empty array of objects with a string `name` | A missing or empty file → state 2 (LAB_0136e8f8) |
| H4 | `bald___hashes___.txt` is non-empty and parses as a JSON array of `{name:str, file_size:int, chunk_size:int>0, hashes:[str]}`, with `len(hashes) == ceil(file_size/chunk_size)` and `file_size` < 2^31 | int32 reads in G:0x136feb0 / G:0x1374560 |
| H5 | The toc has no duplicate names, and every toc name has exactly one hashes entry with the same name | Otherwise "Invalid sync": NULL entry+0x38 → SIGSEGV at ELF 0x419ea8 inside G:0x136feb0, whether or not the file exists |
| H6 | Every toc name starts with `"bald_"+n+"_"`, where `n` comes from the request (`android_astc_h`) | The prefix length is stripped without checking the text; a texture-variant change would otherwise accept wrong-format files |
| H7 | The toc is not our old marker: there is no asset named `*_map_android_dlc_1`, and no payload file is exactly `<dlc/>` | The old empty map → +0x94 = -1 → SIGSEGV at ELF 0xb63614 |
| H8 | The toc contains key `map_android_dlc` (here `…_map_android_dlc_97`), and that file exists with size == `file_size` | Wrapper case 0 pushes the lookup result without a NULL check → G:0xc64570 → ELF 0x8e1728 on NULL. A missing map file also leaves wrapper case 4 waiting forever. |
| H9 | Map-file validation (§3.5): the root is `<dlc>`, exactly one location `name="z0_mp"` exists, and every pack name in `<mandatory>` and in every location resolves to a toc key | No z0_mp → +0x94 = -1 → crash at 0xb63614 (the pointer at ELF 0x1bb2990 → 0x14a4b37 `"z0_mp"`). An unresolved pack → NULL from the operator[] map (ELF 0xb64508) → crash at 0x8e1728, called from 0xb62688/0xb62884. |
| H10 | If `requireSizes` is true: every toc asset that exists has `st_size == file_size` | BALD accepts files on existence alone (ELF 0x12707a0 → 0x12707dc; no size check while +0x139==0). A truncated file would be mounted. **[INFERENCE]** the gla2 reader may crash on it. |
| H11 | If `verifyMd5` is `"strict"`: every chunk md5 matches | Optional; see "Optional md5" below |

**Soft findings.** These only produce log lines; `ok_index` stays true:
- **S1:** a toc asset file is missing. Its BALD entry stays at state 0, so its location's +0x18 is 0 and the location is not mounted. The UI then shows `loading` for z0_mp, or `not_loaded`/`locked` for other zones. Log the zone and the asset name.
- **S2:** `temp_<name>` exists while `<name>` is missing. When that location is wanted, BALD's resume path will request the remaining chunks.
- **S3:** a toc-named file appears somewhere else (depth 3 under `<base>`, or under `importDir`), or a near-miss name appears in `bald/`. Near-miss means the same key with a different `_<rev>`, an extension, or a different case. Log `"rename X -> Y"` advice. The server never renames anything itself.
- **S4:** extra files in `bald/` that are not in the toc. They are harmless, since BALD never scans the folder.
- **S5:** the free disk space in `<base>` is less than 1e6 + Σ(file_size of missing assets). This mirrors G:0xc64570 and G:0xc92a78: the wrapper shows popupNotEnoughSpace.

**Optional md5 (`verifyMd5`).** BALD does not need it. It is a diagnostic for corrupt backups.
- Implement RFC 1321 MD5 in-repo as server/core/md5.{hpp,cpp}. No third-party code.
- Hash each file in `chunk_size` blocks with `pread`, and compare each block with `hashes[i]`, lowercase hex.
- Cache the results in `<files>/MC5Offline/bald_verify.json`, keyed by `{name, size, mtime}`, so only the first boot pays for the 833 MB. That cache lives outside `bald/`.
- `"log"` logs mismatches. `"strict"` turns any mismatch into an H11 failure.

### 3.5 Map-file validation (H9)

The map is pugixml XML, loaded by G:0xcbcec0 with options 0x74 (parse_default). Shape (verified from parser G:0xc62430):

```xml
<dlc>
  <mandatory>
    <ANY name="vehicles_dlc" size="3752065"/>   <!-- element names below are NOT checked -->
    …
  </mandatory>
  <locations>
    <ANY name="z0_mp">
      <ANY name="z0_mp" size="27584233"/>
      <ANY name="z0_mp_ktx_part1" size="31855936"/>
      …
    </ANY>
    <ANY name="z2_downtown"> … </ANY>
  </locations>
</dlc>
```

**[INFERENCE]:** the actual location names and packs above are guesses. The player's 3018-B file is the authority.

The scanner can be minimal, with no XML library needed:
1. Tokenise the tags, skipping `<?…?>`, `<!--…-->` and `<!…>`.
2. Track the depth.
3. Collect the `name` and `size` attributes. Values are `"…"` or `'…'`; decode `&amp; &lt; &gt; &quot; &apos;` entities.
4. Require the root element to be `dlc`.
5. Treat the children of `mandatory` as packs, the children of `locations` as locations, and the children of each location as packs.
6. For each pack `P`: compute `key = lower(P + ".gla2")` with `.` replaced by `_`, then require `key ∈ tocKeys`.
7. Record the location names and log them. They tell us which zones will appear as loaded.

If the map file is unreadable or unparseable, H9 fails (keep the 404).

The parse result also drives per-location completeness logging. A location shows as loaded only if all of its packs are present, and for location index > 0, location 0 must also be complete (G:0xc63728). Log that as follows:

```
[bald] location z0_mp: 11/11 packs present -> will mount
[bald] location z3_venice: 9/9 present (also needs location 0 'z0_mp' complete) -> will mount
```

### 3.6 Replies (asset.cpp, the `assets/{clientId}/{name}` route, `bald_name()` matched)

Decision table. `n` is the variant from `bald_name`, and `rest` is the suffix.

| Request | Condition | Reply |
|---|---|---|
| `bald_<n>___index` (3 underscores; no Range is sent, G:0xd8d810 only adds Range when `from_offset>=0`) | `mode=="mirror"`, `ok_index`, and the crash guard allows it | **200**, `Content-Type: application/octet-stream`, `Content-Length: <len>`, body = `index_bytes`. Ignore any Range header. For HEAD: the same headers, no body. |
| same | otherwise | the current held 404 (`holdMs`) and a log line naming the failed gate(s) |
| `bald_<n>__toc_<x>` (2 underscores) | **always** | held 404, plus a warning (§6.2). Never answer it. |
| `bald_<n>_<asset>` with `Range: bytes=F-T` | `serveRanges`, the asset is in the hashes table, and a **verified source** (below) exists | **206 Partial Content**, `Content-Range: bytes F-T/<file_size>`, `Content-Length: T-F+1`, body = exactly the source bytes [F..T] |
| same | no verified source | held 404, logged once per asset |
| a bald asset without Range | — | 404 plus a warning. BALD always sends Range for payloads. |
| anything else bald_* | — | held 404 |

An example of the exact index exchange:

```
GET /asset//assets/1924:56128:6.0.12a:android:googleplay/bald_android_astc_h___index
→ HTTP/1.1 200 OK
  Content-Type: application/octet-stream
  Content-Length: 3

  244            (0x32 0x34 0x34)
```

Any of 200, 201, 202 or 206 counts as success (HTTP layer G:0xd76850, ELF 0xc76a6c, mask 0x47). Add `case 206: return "Partial Content";` to `status_text()` in server/core/server.cpp; today it falls through to "OK", which the client accepts anyway.

**Range validation:**
- Accept only the single form `bytes=F-T`.
- Require `0 <= F <= T < file_size`.
- BALD's own maths (ELF 0x1273c78-0x1273ca8) is `F = i*chunk_size` and `T = min(F+chunk_size, file_size)-1`. Log a warning if a request does not align with it, but still serve it.
- Any other form: 404.

**Verified source for a Range.** Search in this order, read-only:
1. `importDir/<name>`;
2. a toc-named file found elsewhere under `<base>` (S3);
3. **never** `<bald dir><name>`: if it existed, BALD would not ask;
4. **never** `<bald dir>temp_<name>`: BALD is writing that file.

A source is accepted only if its `st_size == file_size`. Before sending chunk `i = F/chunk_size`, compute that chunk's md5 and compare it with `hashes[i]`. On mismatch reply 404, so the asset stalls rather than looping.

Why: BALD fwrite's whatever body it gets, with no length check (ELF 0x127421c). After the rename it re-validates the size and every chunk md5 (G:0x1374560). On failure it deletes the final file and restarts from chunk 0, forever (ELF 0x12744ac, w+0x50=2).

**Crash guard.** Before the first index 200, keep `ctx.progress.guard_arm("bald", 60)`. If the app dies within 60 s after it, twice, `guard_allowed("bald")` turns false and the server falls back to the held 404. That fallback is safe: it never deletes anything. Log it as `[bald] guard tripped: serving 404 again (DLC stays not-downloaded, files untouched)`.

**Recheck (state 4).** Every `+0x60` ms BALD re-GETs `___index`; the default is 1,800,000 ms, from the dword at ELF 0x15eacf8, and config may override it **[INFERENCE: not traced]**. G:0x136f528 compares that body with the boot-time body, not with the file:
- equal → state 3;
- different → a dry-run diff (mode 1, no erase) and listener `vtable+0x18(1)`, whose UI effect is untraced.

The server therefore returns the same cached `index_bytes` for the whole process. Never change them.

## 4. Why this never deletes the player's files

BALD's delete primitive is G:0x1374878 → G:0x5cc0d0 (remove). It has exactly these callers. calls.tsv also lists the unrelated G:0xc742e0 downloader.

| # | Delete path | Reachable only via | Blocked by |
|---|---|---|---|
| D1 | Toc-diff erase, G:0x1370880 mode 0 (ELF 0x1270e44 final, 0x1270fc0 temp_) | State 2 after a **successful toc download** (ELF 0x126edb0); it runs before the temp_ writes and the space checks | All `__toc_*` → 404, always. Index = local bytes, so state 1 → state 3 and never state 2. |
| D2 | md5-fail delete in G:0x136feb0 (ELF 0x1270810), when +0x139 is set | +0x139 is set only on a version mismatch (ELF 0x126e628), and that path continues only through state 2 plus a served toc | H1, plus no toc ever served |
| D3 | Bookkeeping remove plus rename (G:0x136e988 ELF 0x126f0e0/0x126f170/0x126f200/0x126f290) | State 2 after a successful toc download | no toc ever served |
| D4 | Worker post-validation or rename failure deletes `<dir><name>` (ELF 0x12744ac) | Only an asset being downloaded, i.e. one absent at boot | Range bytes come only from size- and md5-verified sources. Even if this path fires, the file it deletes was not the player's. |
| — | Any 404 or GET error | none: the worker just sleeps `(w+0x78)*10+10` ms and retries (ELF 0x1273e28-0x1273e78) | — |
| — | "Not enough space" | sets +0x7c=0 via G:0x13710e8 and deletes nothing | — |

Our own code is the other delete risk:
- `diag::remove_offline_bald_cache` (diag.cpp ~436-509, called from bootstrap.cpp:69) runs `rm_tree(d,2)`, which unlinks every file in `bald/` if any single file of 4 KB or less matches our old markers.
- `rm_caches_in` also enters `bald/`. It deletes only fed_links.bin, compliancy.bin, `*_cache.bin` and `atlas*.dat` of 64 B or less, none of which matches a `bald_*` name.

Required changes:
1. Replace `rm_tree` with **log-only** in every mode: `[diag] bald: stale offline marker <path> (harmless; BALD ignores files not in its toc; delete it by hand if you like)`. BALD never scans the folder, so a stray 6-byte `bald_android_astc_h_map_android_dlc_1` is inert unless the toc names it, and H7 refuses that case.
2. Make `rm_caches_in` skip any directory named `bald`.
3. Remove `remove_offline_bald_cache()`'s dependency on `bald.serve`.

What the player must back up **before** installing a build with the mirror:
- the whole `.../files/bald/` folder, copied off the device (about 833 MB plus the 4 txt files);
- `.../files/dlc.dat` and `.../files/dlc_mnd.dat` if present. Their location is unverified **[INFERENCE]**: they are opened via fs location 2 by G:0xc63bc0.

Two reasons for the backup:
- The *current* build's `rm_tree` sweep runs at every boot and could wipe the folder if a marker file is present.
- Any future bug that serves a toc would trigger D1.

Also tell the player: if `bald/` contains a 6-byte file `bald_android_astc_h_map_android_dlc_1`, or any file containing exactly `<dlc/>`, delete it **before** the next launch of the current build.

## 5. Behaviour matrix (what the player sees)

| Local state | Server reply | BALD | Game |
|---|---|---|---|
| All 52 files present, H1-H10 pass | index 200 "244" | state 1 → 3 (ready), 52 `exists` calls, no md5 | Wrapper case 0 → 4: map parsed and every complete location mounted (G:0xc62d68 → G:0xc63258, archive flag 4). Then `+0x9c=1` (ELF 0xb62954) and `+0x94`=idx(z0_mp). `isMultiplayerLoaded` (G:0xb1cf38 → G:0xc63620) = 1, and zones read `loaded` (G:0xc63728). No further BALD traffic for 30 min. |
| Some payloads missing | index 200 | ready; missing entries stay at state 0 | Complete locations mount. An incomplete one shows `loading`/`not_loaded`. If z0_mp is incomplete, once the menu sets +0x3c (G:0xc636e8) the wrapper auto-queues the missing z0_mp packs (G:0xc62e08); other zones are queued only after the player requests them (/dlc.dat). The worker GETs Ranges: served if a verified source exists, otherwise held 404 forever. The download stays stuck, but nothing crashes or is deleted. If both workers are stuck and worker 0 is one of them, the 30-min recheck also stalls, which is harmless. The worker count comes from config (G:0xc619d8 ELF 0xb61b30); the default is 2. |
| Version, toc, hashes or index file missing or empty | held 404 (gate fails) | stuck in state 1 | Same as today: not downloaded. Nothing deleted. |
| Map lacks z0_mp, or a pack does not resolve (H9 fail) | held 404 | stuck in state 1 | Same as today, which avoids the crashes at 0xb63614 / 0x8e1728 |
| Truncated file (H10 fail) | held 404, unless `requireSizes=false` | — | If relaxed, BALD marks it ready and mounts it **[INFERENCE: gla2 reader behaviour unknown]** |
| Wrong texture variant (device requests `bald_android_etc_*` or `_l`) | H6 fails for that `n` → 404 | stuck | The player's _astc_h files are unusable on that device or config (G:0xc61858: `getDataUsing()=="ASTC"`, app+0x566 `isHighTextureData`) |

Side effects seen in the UI:
- Before the map is parsed, the zone list G:0xa53eb0 shows every zone as `loaded`, because a location index < 0 is treated as loaded. The detail view G:0xa5b708 shows the true state. This inconsistency also exists today.
- If the /dlc.dat wifi-only flag (+0x9e) is set and the connection is not Wi-Fi, the wrapper enters paused state 3 (G:0xc92a50). This only matters for downloads.

## 6. Log lines to implement (exact text)

```
[bald] dir candidates: <p1> (index=yes|no) | <p2> (...) ...  -> using <dir>|none
[bald] bookkeeping: index=<len>B "<printable>" version="<v>" toc=<len>B assets=<k> hashes=<len>B entries=<m>
[bald] gate <H#> FAILED: <reason>          (one per failure)
[bald] map <name> (<size> B): locations=[z0_mp,z2_…] mandatory=<k> packs=<p>, all resolve
[bald] location <loc>: <a>/<b> packs present -> will mount | incomplete (missing: …)
[bald] assets: <present>/<total> present, <bytes> B; missing=<k> (<bytes> B); size-mismatch=<k>
[bald] near-miss: '<found>' looks like '<toc name>' (rename it in files/bald/)
[bald] md5 (<mode>): <ok>/<checked> chunks ok [<ms> ms] | mismatch <name> chunk <i>
[bald] mirror READY: index will be served as <len> B
asset: BALD bald_android_astc_h___index -> 200 (<len> B local index, mirror) [#<k>]
asset: BALD bald_android_astc_h__toc_<x> -> 404 (toc is never served; index mismatch? local index="<…>")
asset: BALD <name> range=bytes=F-T -> 206 (<len> B from <source>, md5 ok)
asset: BALD <name> range=bytes=F-T -> 404 (no verified local copy; BALD will retry)
[bald] guard tripped: serving 404 again (DLC stays not-downloaded, files untouched)
```

### 6.6 Code-review checks (blocking)

- `grep -nE 'unlink|remove\(|rename\(|rmdir|fopen\([^)]*"[wa]' server/services/asset.cpp server/services/bald*.cpp` must find nothing that touches a BALD path.
- `grep -n '"1"\|__toc_1\|<dlc/>' server/services/asset.cpp` must return nothing.
- Unit tests, desktop build, using a synthetic fixture folder generated in the test (no Gameloft data):
  - H1-H10 each fail on their own when broken;
  - an index reply is exact bytes for "244", including a reply with a trailing `\n` in the file (that must fail H2);
  - the Range maths for the last partial chunk;
  - toc requests always return 404;
  - the sweep never unlinks anything.

## 7. Device-test checklist

1. **Back up** `files/bald/` off the device. Check that no `<dlc/>` or `_map_android_dlc_1` file is present.
2. Install the build and launch. In `mc5offline.log`, expect:
   - `[bald] dir candidates … -> using /sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/bald/`. If it picks `/data/data/...` instead, **[INFERENCE]** §1 is wrong; note it.
   - `bookkeeping: index=3B "244" version="6.0.12a" toc=2892B assets=52 hashes=121072B entries=318`
   - `map bald_android_astc_h_map_android_dlc_97 (3018 B): locations=[…z0_mp…]`. **Record the location list**: it is the first time the map contents are seen.
   - `assets: 52/52 present, 832976516 B; missing=0`
   - `mirror READY`, then exactly **one** `asset: BALD bald_android_astc_h___index -> 200 (3 B …) [#1]`.
   - **No** `__toc_` lines, **no** `range=` lines, and no more `___index` lines for about 30 min.
3. In the menu:
   - the campaign zones (Downtown, Venice, Construction, Blackwater) show as available rather than download;
   - entering MP opens no `popup_DownloadProgress`;
   - no SIGSEGV at 0xb63614 or 0x8e1728 (tombstone or logcat).
4. Play one mission in a DLC zone and one MP map, to confirm they load (exercising the gla2 mount and `_snd` banks).
5. Leave the game in the menu for more than 30 min. Expect a second `___index -> 200 [#2]` and nothing else.
6. Afterwards, compare the folder against the backup with `ls -l` and `md5sum` on the four txt files: they must be **unchanged**. Also confirm no `temp_*` files appeared.
7. Negative test, optional: rename one z3_venice pack. Expect:
   - `location z3_venice: 8/9 … incomplete`;
   - the index is still 200;
   - Venice shows `not_loaded`, the other zones are fine, and nothing is deleted.
   Restore the name afterwards.

## 8. Open risks

1. **The map contents are unverified.** The location names, the mandatory packs, and whether the UI's zone names (campaignZone[i]+0xe8, G:0x9e2840) equal the map's location names are all unknown. H9 makes a bad map fail safe, but which zones show as loaded depends on that file. The first device log (step 2) resolves this.
2. **The BALD base dir** (`FUN_005be028()`) has not been traced. The probe-and-log in §3.1 covers it.
3. **Existence-only acceptance.** A file with the right size but wrong content (corrupt backup) is mounted. Use `verifyMd5:"log"` to detect it; the gla2 reader's behaviour on it is unknown.
4. **The state-4 "different index" callback** `vtable+0x18(1)` is untraced. It is avoided by never changing `index_bytes`.
5. **The recheck interval and worker count** come from runtime config (`*(*(0x1bbdee0)+0x40)` for workers; the interval override is untraced). Neither affects correctness.
6. **The boot loader G:0x933050** waits on +0x9c in case 3 when `/dlc_mnd.dat` is absent or stale. With BALD now becoming ready this should resolve itself; the online-era `/dlc_mnd.dat`, if present, is reused **[INFERENCE]**.
7. **The texture variant must stay `android_astc_h`.** If the patched APK changes `getDataUsing()` or `isHighTextureData()`, none of the player's files apply (H6 refuses the other variant).
8. **The current build is the danger.** Until this build replaces it, the `rm_tree` sweep can wipe the folder if a marker is present (§4). The player's off-device backup is the only mitigation.
9. **Missing assets stall a BALD worker permanently** (no give-up path exists: worker +0x74 is never set to 1). The only fixes are restoring the file under its toc name or supplying it via `importDir`.