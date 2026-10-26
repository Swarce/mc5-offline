# 00 – Recon: Modern Combat 5 for Android 6.0.12a

Analysis only; nothing is built yet. Status: first pass (October 2026). Items marked **open** are planned for Phase 1b
(see the end of this document).

Tags: **[V]** verified by reading the code, **[L]** likely (strong inference), **[S]** speculative.

## Inputs

| File | SHA-256 | Notes |
|---|---|---|
| `Modern.Combat.5.ver.6.0.12a.build.601213.apks` | `2c1c13e0bc3ca4ee018adaf36ee8aead09639a491439056ee8844dee31ec3966` | Split set exported from the S22 |
| `base.apk` | `0236de50566a265d4ee1b99e62c076b2741d94e771cc691477f22e72e84d6770` | 11 dex (9 in the root, 2 in `assets/audience_network`), v2+v3 signature, Play source stamp |
| `split_config.arm64_v8a.apk` | `c24f8c3b9953e00d766b99481152ba0e0513043543047a6a53e9426dcfe6d523` | `lib/arm64-v8a/*.so` (19 libraries) |
| `split_config.xxhdpi.apk` | `5f8eb8588fce5e1c6076bb83e4522f9daf2a9c49a857dfe33dc95174db332e5f` | density resources |
| `libMC5.so` (inside the ABI split) | `5834acb133277a466f915adc84c786495c72e6ccad7d9b9b15715e34384c3751` | 29,065,768 bytes, build-id `475ac80eb88f7bffac8cb3b0a532c66852b94654` |

Package `com.gameloft.android.ANMP.GloftM5HM` [V] (manifest), versionName 6.0.12a, versionCode 601213, minSdk 24,
targetSdk 36. **Missing:** the five Play Asset Delivery packs that hold the game data, the 32-bit ABI split, and the
`Android/data` and `Android/obb` folders. The backup checklist is in [../BACKUP.md](../BACKUP.md).

Shutdown date: **not confirmed.** No Gameloft announcement for the mobile version was found (searched 2026-10-26).
Community posts report that the Steam version's servers closed on 1 December 2023 and that the Microsoft Store version
kept working.

Address convention: Ghidra loaded `libMC5.so` at image base `0x100000`, so **Ghidra address = ELF address + 0x100000**.
This document cites Ghidra addresses ("G:0x...") unless it says "ELF".

## 1. Engine and stack

| Question | Answer | Evidence |
|---|---|---|
| Engine | **Native C++** (Gameloft "Glitch" engine), not Mono/Unity. No .NET assemblies in the APK | `libMC5.so`; `GLITCH_*` shader defines; source paths `E:\MC5\porting\trunk\{game,extern}\...` [V] |
| Toolchain | Android clang 9.0.9 (NDK r21 era), static libc++, `BIND_NOW` | `.comment`, `readelf -d` [V] |
| Size | 89,493 functions (eh_frame), 96,165 after Ghidra analysis; 6,769 exported dynamic symbols (asio, libc++, firebase, `acp_utils`, flatbuffers, `ysM`, a few `glitch`); 152 JNI exports | `nm -D`, Ghidra export [V] |
| Middleware | GaiaV2 online SDK **15.0.0**, libcurl **7.88.1** + OpenSSL, asio (TCP), Lua 5.1, gameswf (Flash UI), Vox audio, libpng 1.6.17, harfbuzz, zstd, Vivox voice (`libvivox-sdk.so` is a `DT_NEEDED` of `libMC5.so`) | string `GaiaV2_LibVersion_15.0.0` (G:0x16c92cc), `CLIENT libcurl 7.88.1-DEV`, `readelf -d` [V] |
| Java layer | Gameloft Android shell (MainActivity, GameInstaller v3.7.25019, Play Core asset packs, billing, ads SDKs, Firebase, Didomi consent) | jadx [V] |
| ABIs | Only `arm64-v8a` in the provided set. The base manifest requires ABI and density splits (`requiredSplitTypes="base__abi,base__density"`, `com.android.vending.splits.required=true`) | manifest [V] |
| Obfuscation | Java: R8 renaming of many classes and members; the public JNI-facing API keeps its names. Native: unstripped exports, no RTTI for game classes; some strings are built one character at a time in static initialisers (service names such as `pandora` and `federation`, GLOT strings) | jadx; G:0x46a850, G:0x46bc08 [V] |

### 1.1 Anti-tamper, signature and integrity checks

| Check | What it does | Consequence | Evidence |
|---|---|---|---|
| Java `SignatureChecker` | Returns the signing certificate's MD5/SHA-1/SHA-256, the PEM, or the installer package name, through JNI `AndroidUtils.GetSignature(int)` | Read by native `acp_utils::api::PackageUtils::GetSignature` from two places (G:0xddc918, G:0x143a5f8). No local comparison found so far: **[L] reported, not enforced** | `SignatureChecker.java`, `AndroidUtils.java:473` [V] |
| Native `ysM` ("APK manager") | `GET_ALL_SIZES` builds a `size|size|...|sum|count|time` string of APK entries; `ftC` hashes `<libdir>/libMC5.so`; `GetImgCs` computes a digest keyed with `"modern_combat vs"` | `GetImgCs` is called only when the **game server asks for it** (message type `':'` in both TCP dispatchers, G:0xcf72d0 and G:0xd09780), and the result is sent back. `GET_ALL_SIZES`/`ftC` go to G:0x143a748/G:0x143a460 (reporting). **[L] integrity is checked server-side**; our server simply does not enforce it | G:0x50aac0, G:0x50acc8, G:0x50baa0 decompiled [V] |
| `ysM::CheckOfflineZoro()` | Identical-code-folded with an empty `ret` | The local "offline" check is compiled out | ELF 0x409060 is `ret` [V] |
| "Unofficial" popup | `MainActivity.<clinit>` loads `vivox-sdk` and `MC5`; if that fails, `CustomPopup.ShowUnofficialWarn()` ("Application not supported") | Only a missing library triggers it; keep every library | `MainActivity.java:1060-1064, 1437` [V] |
| Play Integrity / LVL | None in the Gameloft Java code | – | grep [V] |
| Root strings | `/system/xbin/su` and others | Feeds tracking (`device is rooted`); no enforcement seen **[L]** | strings |

Conclusion: no local check stops a modified APK **[L]**. All integrity data goes to Gameloft's servers, which our
server replaces. Fingerprint-verified patches are still the rule, and the recommended design (§6) changes almost no
game bytes anyway.

## 2. Online stack

### 2.1 Discovery: eve, then pandora

* Hard-coded `https://eve.gameloft.com` (ELF string 0x14ad840, used by G:0xc7bb10) [V]. The Java push-notification
  code builds the same requests: `https://eve.gameloft.com:443/config/<clientId>/datacenters` → array of
  `{name, status, preferred}`; the one with `status:"active"` and `preferred:true` wins; then
  `.../datacenters/<name>/urls` → object (or array) with a `pandora` field (`RemoteImageManager.java:223-300`) [V].
* Client id **`1924:56128:6.0.12a:android:googleplay`**; QA tag `BETACLONE` switches to `1924:56128:0.0.12a:...`
  (`RemoteImageManager.GetClientId`) [V].
* Native Gaia uses the same paths (`/config/`, `/datacenters`, `/datacenters/`, `/urls`: G:0xd86290, G:0xd868e8) [V].
  **After parsing eve's `urls`, Gaia rewrites the `pandora` and `federation` values from `http://` to `https://`**
  (G:0xd85c40 → G:0xd85db0, G:0xd86020; the keys are the obfuscated static strings at G:0x1cc9a88/G:0x1cc9c38) [V].
* Then `pandora/locate?service=<svc>` (path `/locate`, G:0xda5428). The Java copy treats the answer as a bare host
  and prefixes `https://` itself (`RemoteImageManager.java:193`) [V].
* A second, newer discovery stack (IRIS config providers: Consent, KillSwitch, BehavioralMgr) repeats
  eve → pandora → `/locate?service=asset&client_id=` → Iris and caches the URLs on disk (G:0x1486180, G:0x1486a28) [V].

### 2.2 TLS and pinning

Gaia's HTTP layer (G:0xd4c820) sets `CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST` to 1 and `CURLOPT_CAINFO` only when a CA
path is configured, and to 0 otherwise [V]. No CA-bundle path for Gaia exists in the binary (the only `ca-bundle.crt`
belongs to Vivox) **[L] certificate verification is off**. The other curl users set `VERIFYPEER 0` unconditionally:
the IRIS config client (G:0x1484168), a second generic HTTP client (G:0x146b9c0), another Gaia request path
(G:0xd75de8) and the ads SDK (G:0x58dfc0) [V]. curl's pinning strings are present, but no `CURLOPT_PINNEDPUBLICKEY`
call was found [L]. Java's network security config allows cleartext to `127.0.0.1` and
`gameloft.com` (`res/xml/network_security_config.xml`) [V].

**Consequence:** a loopback HTTPS server with a self-signed certificate should be accepted without any client patch
(to be confirmed on the device in the first test).

### 2.3 Federation services and endpoints referenced by the client

From the path literals in the Gaia layer (G:0xd00000-0xe2ffff) [V]; the method, parameter and response details per
endpoint are **open** (Phase 1b):

| Service (MCVS name) | Paths seen |
|---|---|
| eve / pandora | `/config/`, `/datacenters`, `/datacenters/`, `/urls`, `/locate` |
| auth (Janus) | `/users/`, `/users/me`, `/users/me/transfer_code`, `/games/mygame/alias[/]`, `/get_third_party_auth_token`; account/platform names in this layer: anonymous, googleplay, facebook, gllive, gamecenter (and store names huawei, samsung, amazon) |
| social (Osiris) | `/accounts/`, `/accounts/me`, `/accounts/me/connections/`, `/accounts/me/requests[/]`, `/accounts/me/import`, `/accept`, `/ignore`, `/abuse`, `/wall` |
| groups / clans | `/groups/`, `/groups/categories/`, `/members[/]`, `/find/recommendation_score` |
| messaging (Hermes) | `/messages/`, `/transports/`, `/endpoints[/delete]`, `/multicast` |
| alerts (Kairos) | `/alerts/me`, `/alerts/subscribe`, `/alerts/targets` |
| leaderboards (Olympus) | `/me`, `/me/`, `/me/location`, `/me/friends` |
| CRM config | `/configs/users/me` (also `/configs/status/users/me/updates|matched_fields`) |
| assets (Iris) | `/assets/<clientId>/<name>` (also used for the BALD DLC, §4) |
| matchmaker / lobby | `/rooms/`, `/quick_join`, `quick_join_ah`, `/automatch/` |
| ecomm / IAP | `ecomm_api_root`, `/transactions/me/gifts`, receipt validation, `buy_product`, `verify_transaction`, ... |
| tracking | ETS/ETSv2, GLOT (`events.json`), Hestia tracking config, `ingamenews.php`, `hdloading.php` |

### 2.4 Auth, save and what the campaign needs (first-pass findings)

* **The player profile is held by Gameloft's game server, not only on the device.** The TCP meta channel (§3.2) pushes
  `TCP_Profile`, `TCP_Inventory_Changes`, `TCP_Config`, `TCP_LVLFile` and `TCP_Tournaments` to the client
  (G:0xd09780 case pairs `0x03`/`0x27`, `0x45`/`0x46`, `0x3e`/`0x3f`, `0x07`/`0x29`, `0x04`/`0x28`; config and
  tournaments are decompressed into 1 MB buffers) [V].
  This matches the 2014 launch statement that the campaign needs a connection because progression is unified [L].
* Local files: the save folder is `getFilesDir()` (`SUtils.getSaveFolder`) [V]; the native side has `settings.dat`,
  `ur.dat`, `hc.dat`, `dc.dat`, `briefings.dat` and others [V]; their role relative to the server copy is **open**.
* Offline hooks exist and must be read before deciding: `federation_offline`, `no_fed`, `offline`, `guest_mode`,
  `playAsGuestPopup`, `offline_store`, and a debug option `force_local_profiles` [V strings; behaviour open].
* Age and playtime restrictions call an ecomm "Restrictions" service (`CheckUsersStateOnServer`,
  `GUEST_TIME_LIMIT_EXCEEDED`) [V strings]; we answer permissively.

**Working assumption [L]:** without the backend the campaign cannot load the profile, so even single-player needs
our game server's meta channel, not just Federation.

## 3. Multiplayer architecture (the key question)

### 3.1 Matchmaking: Gameloft-hosted dedicated servers through Anubis

* The client asks the matchmaker for `quick_join_ah` with `server_type=ahgameserver`, `creator_datacenter`, and gets
  `room_id`, `controller_host`, `controller_tcp_port` (error `AUTOMATCH_AH_TCP_TOO_SMALL`) (G:0xd071d8) [V].
* It then speaks the **Anubis lobby/controller protocol** (newline JSON over TCP), the same family MCVS uses
  (G:0xd37cb0-0xd3d738) [V]: the server sends `create connection` with a `nonce`; the client sends `login`, then
  `connect game {room_id, username, access_token, nonce_type}` and gets a `slot`. Lobby commands: `create room`,
  `create team room`, `join room {room_id, reservation_code}`, `reserve`, `remove reservation`, `launch game`,
  `get game controller`, `get room info`, `leave room`, `update room`, `update user`. Room fields: `room_id`, `name`,
  `lobby_host`, `lobby_tcp_port`, `controller_host`, `controller_port`, `game_started`, `full`, `capacity`,
  `available_slots`, `members`, `reservation_codes`, `custom_attributes`, `client_id`.
* The `ahgameserver` processes run on Gameloft's machines; **no server binary ships in the APK** [V: no server
  executable or headless world in the APK].

### 3.2 Game transport after `connect game`

* **TCP only [L].** Sends go through the controller socket (G:0xcf2570 → G:0xd40a60); a legacy direct TCP connect to
  a host:port also exists (G:0xcf2160, cf. the `no_legacy_server_connect` key) [V]. The only `sendto`/`recvfrom`
  users are a "remote controller"/companion-device feature (G:0x9cb9a0-0x9ce340) and a ping helper (G:0xd1a480) [L];
  no gameplay UDP was found.
* **Framing [V]:** `[type: u8, 1..0xAD][length: u16 big-endian, includes the 3-byte header][payload]`; 256 KB receive
  buffer; one message per callback (G:0xce6e20 → G:0xcf7178). Payload fields are big-endian primitives and strings,
  written by a small writer (G:0x9cff28 begin, G:0x9cfe60 type, G:0x9cfdd8 string, G:0x9cf520 u32, G:0x9cd7e8 length
  fix-up). **No encryption or compression of the frame** (large blobs inside are compressed) [V].
* Dispatchers: G:0xd09780 (~55 message types: profile, inventory, config, tournaments, level file, rating, alias,
  JSON events) and G:0xcf72d0 (~20 types: data files, JSON, integrity request `':'`, pause/deploy UI); the
  **in-match replication layer** is around G:0xbd0000-0xbe4000 (506 functions, game modes `battle`, `teambattle`,
  `vip`, `ctf`, `elimination`, `payload`, `duel`, zombie modes, `OnNewPlayerConnected`; parsers read quantised int16
  positions and entity lists) [V for the structure]. Client senders: 22 builders around G:0xcf7f10-0xcf8b10 and
  G:0xd0d250 [V].

### 3.3 Authority, bots and host code

* **Authority model: open.** The server sends world-state lists (positions, entities, snapshots: `SnapShot`,
  `RequestAgainSnapshot`), level files and configuration. Whether hits and damage are decided by the server or
  claimed by clients is the main Phase 1b question.
* **Bots:** the matchmaker takes `&_botsOnly=` (G:0xce70a8) and the client creates `bot_credentials_%d`
  (G:0xc42270); the client also has debug code that spawns MP bots with an `mpId` and `UpdateBotPlayers`
  (G:0xc41a80) [V strings]. Whether bot AI runs on the server or on a client is **open**. If a client drives bots,
  bot matches are much cheaper for us.
* **No listen-server or LAN host code was found [L].** `MultiplayerCreateLocal`, `JoinLocal`, `SearchLocalGame`
  and `LeaveLocalSearchingGame` are strings with no code references (leftovers from MC4); `StartLocalGame` is only
  reused as the UI event that starts an ordinary match (G:0x9eb990, G:0x937588) [V]. The `listen`/`accept` callers
  are curl and the debug remote controller [L].

**What our game server must reimplement:** the Anubis lobby/controller, the meta channel (profile, inventory,
economy, tournaments, config files), and the match server (match flow, world-state replication, scoring and
objectives per mode, results). Unlike MCVS, none of this ships in the client, so it is a real reimplementation driven
by the client's parsers and builders. The size of the match server depends on §3.3: a "thin authoritative" server
(rules, timers, spawns, scoring, relaying player state, trusting client hit reports) is a large but bounded job; full
server-side simulation (movement validation, server hit registration, server-side bot AI with navigation) is far
larger. One phone can host either, since the server needs no rendering.

## 4. Content delivery

* **No OBB.** The installer still knows `Android/obb/<pkg>` (`GameInstaller.marketPath`), but the data comes from
  **Play Asset Delivery**: `assetPack_HighSlow0` … `assetPack_HighSlow4` (`MainActivity.java:1069-1073`), fetched by
  Play Core (`AssetsManagerPlugin`), located with `getPackLocation(...).path()` and read by native through JNI
  `AndroidUtils.RetrieveAssetPacksPath0..4` → `<pack>/data_HighSlow`, or `data_HighSlow#tcf_astc` on ASTC devices
  [V]. They are fast-follow or on-demand packs (the code asks Play to fetch them and shows the cellular confirmation),
  so they live in internal storage [L]. A re-signed APK cannot get them from Play, so the offline build must point
  these paths at a local copy (§6.3).
* **Runtime DLC ("BALD") [V]:** G:0x136c000-0x1376000 keeps `bald___index___.txt`, `bald___version___.txt`,
  `bald___hashes___.txt`, `bald___toc___.txt` and downloads `assets` by `asset_name` in ranges (`from_offset`,
  `to_offset`, `chunk_size`, `file_size`) with hash validation; mandatory DLC gates the boot (`STATE_MandatoryDlc`,
  `dlc.dat`, `dlc_mnd.dat`, `map_android.dlc`, `vehicles_dlc`). The source is the Iris `assets` service reached
  through pandora [L]; it dies with Federation. **Mirror:** the safest source is the player's own `Android/data` backup
  after a full download; a `tools/cdn-mirror`-style downloader for the BALD toc and chunks is possible while the
  service lives, but it needs the live Gaia auth, so it is optional and needs your approval.
* GameOptions: `GO_android.json` ships in the APK (119 KB); the installer keeps an ETag for a refreshed copy and the
  native side knows `gameoptions.gameloft.com` [L]; the shipped copy should be enough.

## 5. Other platform builds

| Build | Status | Useful? |
|---|---|---|
| Windows (Steam) | Delisted; servers reported closed on 1 December 2023 | Only if you still have the files: a desktop build of the same engine is easier to read (x86-64, possibly more symbols) |
| Windows (Microsoft Store) | Reported still listed and online | Same reason; UWP packages are encrypted unless taken from an install |
| Nintendo Switch ("Modern Combat Blackout", 2019) | Needs a modded console to dump | Not recommended |
| iOS | App Store | No advantage over Android |
| Older Android versions (your own) | – | Cross-reference only (string and code diffs) |

None of them contains the game server, and none is needed for the plan below.

## 6. Proposed architecture

### 6.1 Components

```
patched APK (built from the player's own splits)
├─ libMC5.so (unchanged bytes)
├─ libmc5offline.so  ← ours, C++17, built for every ABI the player supplies
│   ├─ hooks: GOT entries of libMC5's libc imports (getaddrinfo, connect) and of exported PackageUtils getters
│   ├─ Federation HTTPS server (loopback, self-signed): eve, pandora, auth, storage, CRM, social, messaging,
│   │   alerts, leaderboards, assets/Iris (+BALD from local files), matchmaker (quick_join_ah → our controller),
│   │   ecomm/restrictions (permissive), tracking sinks
│   ├─ Anubis lobby + controller (TCP JSON, as in MCVS)
│   ├─ MC5 game server: meta channel (profile, inventory, economy, tournaments, config) + match server
│   ├─ storage: profiles and settings under Android/data/<pkg>/files/MC5Offline/ (atomic writes, backups)
│   └─ diagnostics: logcat tags, boot trace, crash reporter (signal handlers + tombstone text), game-thread watchdog
│       with thread dumps, rolling log copy readable on the phone
└─ dex: one fingerprinted change so MainActivity loads libmc5offline before libMC5
```

The same server source builds as a desktop executable (Linux/Windows) for the development loop and, later, for PC
or VPS hosting of internet matches.

### 6.2 Redirecting the game (options)

| Option | How | Game bytes changed | Pros | Cons |
|---|---|---|---|---|
| **A (recommended)** | Our library calls `dlopen("libMC5.so")` itself, then rewrites libMC5's GOT entries for `getaddrinfo` (all `*.gameloft.com` → 127.0.0.1) and `connect` (127.0.0.1:443 → our port); the server speaks TLS with a self-signed certificate | none in libMC5 | Serves the game exactly what it expects (https, real hostnames); also covers hosts discovered at runtime | Needs the loopback TLS stack (mbedTLS, ~300 KB) and §2.2 to hold |
| B | In-memory patch of the eve literal (`https://127.0.0.1:NNNNN` fits in 24 bytes) and of the `http→https` rewrite | 2 fingerprinted in-memory patches | Plain HTTP server | Touches game code; hosts outside eve's tree still need DNS hooks |
| C | File patches in `libMC5.so` | yes | Simple | Changes the file the game hashes (reported to the server only, but avoidable) |

### 6.3 Patcher

Inputs: the player's base and config splits plus the asset-pack files. Output: one installable APK (splits merged,
`requiredSplitTypes` and `com.android.vending.splits.required` removed), with every supplied ABI and our library.
Patches, each fingerprint-verified with a dry-run mode: (1) the `MainActivity.Vivox_init` library list, (2) asset-pack
location → local folder (Java `AssetsManagerPlugin.getAbsoluteAssetPath`, or a GOT hook of the exported
`acp_utils::api::PackageUtils::GetAssetPacksPath0..4`, which needs no dex change), (3) manifest debloat as in MCVS
(optional). Reproducible builds, one signing key kept by the player across updates.

Language options: **Java/Kotlin** (Google's `apksig`, `dexlib2`, and ARSCLib to merge splits without aapt: all
mature, deterministic) or **C#/.NET** reusing MCVS's binary-XML, signing and zip code, plus a small dex patcher.
Recommendation: Java/Kotlin, because dex and split merging are the new hard parts and the JVM libraries for them
are the reference implementations.

### 6.4 Tests

Unit tests for every service; protocol tests from the client's own parsers (each message documented with its G:
address); and **conformance tests that run the real `libMC5.so`** under qemu-aarch64 with AOSP bionic and stub
system libraries, driving its Gaia and TCP client code against our server (qemu-user is available in this
environment). This is the MC5 counterpart of MCVS loading its real client DLL. The full suite runs before every APK.

## 7. Milestones

1. **M0 – foundation:** repository layout, `libmc5offline.so` loaded by a patched APK with diagnostics (logcat, boot
   trace, crash reporter, watchdog, log copy), hooks in place, Federation answering eve/pandora/auth. Device test:
   the game boots past the installer with local asset packs and reaches the login/loading stage, every request
   logged.
2. **M1 – offline campaign:** meta channel (profile, inventory, economy, config files, tournaments as empty), storage
   on the device, CRM, BALD from local files. Device test: campaign missions play and progress survives restarts and
   updates.
3. **M2 – bot/solo matches on our game server:** Anubis lobby/controller in-process, match server for one mode
   first (Team Battle), then the others; bots either client-driven (if §3.3 allows) or server-side.
4. **M3 – LAN:** one phone hosts (its embedded server binds the LAN address); other phones join by IP or discovery.
5. **M4 – internet:** the desktop server build on a PC or VPS, account and token sharing between devices, optional
   relay.

## Phase 1b (next analysis, before M1/M2 code)

1. Per-endpoint Federation contract (method, parameters, response fields, error handling) for the endpoints the boot
   and campaign hit, driven by the M0 device log.
2. The meta channel: every client builder and server message used by the campaign; the profile blob format.
3. The offline flags (`federation_offline`, `no_fed`, `guest_mode`, `force_local_profiles`): if any of them lets the
   client keep its profile locally, M1 shrinks a lot.
4. Match authority (§3.3) and bot ownership.
