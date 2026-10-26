# 01 – Phase 1b: save, meta channel, Federation requests, match authority

Analysis of the player's own copy of Modern Combat 5 6.0.12a, from the decompiled client only; no Gameloft service
was contacted. Baseline: [00-recon.md](00-recon.md). Tags: **[V]** verified in code, **[L]** likely, **[S]**
speculative. Addresses are Ghidra addresses ("G:", ELF + 0x100000).

Generated catalogs:
- [../protocol/tcp-messages.md](../protocol/tcp-messages.md): every TCP message type with its field order, for the
  meta channel (both directions) and the in-match channel.
- [../protocol/federation-requests.md](../protocol/federation-requests.md): 68 Gaia request builders with their paths
  and request keys.

## Summary

| Question | Answer |
|---|---|
| Can the client keep its profile locally (offline flags)? | **No.** `federation_offline` and `no_fed` are fields of the purchase requests, `guest_mode` belongs to the age/legislation module, `force_local_profiles` selects the bundled GameOptions device profiles [V] |
| Where is the save? | A **JSON profile** pushed by the transaction server (TS) over the TCP meta channel (`TCP_Profile`, LZ4). Other players' cards come from Federation (`game_portal` `get_batch_profiles`, `include_fields=_game_save,inventory`). The client never calls the storage service itself [L] |
| What is the meta channel? | The **TS**, a `ts` room joined through the matchmaker (`quick_join_ah`) and reached through the Anubis controller, the same TS/GS split as MCVS. The TS side is not in the client, so we reimplement it [V for the client side] |
| Federation | Standard Gaia services; eve → pandora → `/locate` for auth, storage, message, feeds, leaderboard, social, asset, matchmaker, lobby, lottery, voice, config, alert, schedule, transaction, groupchat [V]. Auth vocabulary is the same as MCVS's |
| Match authority | **The rules run in the client's shared match code** whenever a peer holds an "authority" role: captures, pickups, deaths, hit reactions, killstreaks, scoring, round end and bots are decided by the role holder and broadcast; the others apply [V for the code paths]. How the role is assigned online is still open [L: the GS assigns it] |

## 1. Offline flags

| String | Where | What it is |
|---|---|---|
| `federation_offline`, `anon_credentials`, `federation_credentials` | G:0xe0c3b0, G:0xe0d668, G:0xe0ff88, G:0xe12500 | Fields of the IAP `pre_buy_registration`/`pre_transaction` requests [V] |
| `no_fed` | G:0xde5538, G:0xe05b28, G:0xe08be8 | IAP code [V] |
| `guest_mode` | static string used only by G:0x14923d0 | "Restrictions" (age, legislation, store type) [V] |
| `force_local_profiles` | G:0x119fe48 | GameOptions device profiles (graphics presets), next to `GameOptionsOverrideSlider` [V] |
| `playAsGuestPopup` | UI | Popup for playing without a linked account, i.e. an anonymous Federation login [L] |

## 2. Profile and save

* The TS sends the profile as message `0x03`/`0x27` (`TCP_Profile`, G:0xd09780). The payload is `u32 length` plus an
  **LZ4 block** (G:0x5dfff0 is LZ4 block decompression), decompressed into at most 1 MB and NUL-terminated
  (G:0xd090e8) [V]. The text is parsed as JSON (jsoncpp, G:0x1150e08) by G:0x5f18a0 and handed to the subsystem
  loaders [V].
* Keys read by the main loader (G:0x6e1498) include: `credits`, `rd_currency`, `sp_difficulty`, `rating`,
  `rating_duel`, `best_solo_rank`, `best_squad_rank`, `statistics`, `skill_use_time`, `killsig`, `season_awards`,
  `tournaments_sem`, `tournaments_cup`, event fields (`event_id`, `event_score`, `event_rank`, `event_tier`,
  `event_league`, `event_milestones`, ...), campaign progress (`ev_chapters`, `m_progress`, `m_challengesProgress`,
  `m_clTimes`, `bMissionTimerSkipped`, `bPlayedOnMap`, `ch_clTimes`, `bChapterTimerSkipped`), `osiris_info`
  (clan), `_inventory_shadow`, `private_profile`, `daily_reward`, `br_daily_reward`, `energy_event`, `created`,
  `alias`, `gender`, `birthdate`, referral fields, `bpacks_vault`, `zmb_achievments` [V]. Other loaders:
  `notifications` (G:0x6dd9c8), achievements with `_sync` (G:0x898680), progress nodes and objectives
  (G:0x74f210), tutorials and `skill_points_spent` (G:0xbb1b60) [V].
* Player cards of other players read `_game_save.inventory.loadouts`, `current_loadout`, `xp`, `rating`,
  `osiris_info.clan_*` from Federation profiles (G:0x7b16a8, G:0xa5eea8, G:0xa0a3d0), fetched with
  `op_code=get_batch_profiles` (G:0xc85078) [V]. So Gameloft's TS mirrored the profile into Federation storage [L].
* The `storage` service name is only defined, never used by client code (G:0x46cd60) [V]; no Seshat paths appear in
  the request builders [V]. The client does not persist its own profile on the device [L].

**For us:** our TS owns the profile document, saves it on the device, sends it as `TCP_Profile`, and mirrors
`_game_save`/`inventory` into our Federation storage for player cards.

## 3. The meta channel (TS)

* **Discovery:** the client runs `quick_join_ah` with server type `ts` (G:0xd071d8 → G:0xd06c98), gets `room_id`,
  `controller_host`, `controller_tcp_port` and an `encrypted_access_token`, logs in to the Anubis controller and sends
  `connect game`; after that the controller socket carries the TS protocol (G:0xcf2570 → G:0xd40a60) [V]. A legacy
  direct host:port connection also exists (G:0xcf2160) [V].
* **Framing:** `[type u8][length u16 BE, includes the 3-byte header][payload]`, big-endian fields, strings
  `u16 length + bytes`, blobs `u32 length + bytes`, compressed blobs `u32 length + LZ4 block` [V]. Data messages come
  in pairs of types that share one handler (`0x03`/`0x27`, `0x04`/`0x28`, `0x07`/`0x29`, `0x3e`/`0x3f`,
  `0x45`/`0x46`): the lower type carries the blob plain, the higher one LZ4-compressed [V]. For tournaments and
  config, a compressed blob larger than one message is reassembled from a first 65,000-byte part kept by an earlier
  message (G:0xd09780) [V].
* **Login:** `ClientSendInitSettings` (type `0x01`, G:0xd08008): `u8 0x33`, `u8 0x0b` (protocol version), `u32`,
  then strings: the client's **pandora URL**, account credential and token strings, the device id, a few flags and a
  final `u32` [V; field meanings L]. The TS therefore talks to Federation on the player's behalf, like MCVS's
  server-side sessions.
* **Server → client** (G:0xd09780, ~55 types; G:0xcf72d0, ~20 types): profile `0x03/0x27`, tournaments
  `0x04/0x28`, level file `0x07/0x29`, config `0x3e/0x3f` (an empty config is accepted: the client applies a default
  config event, G:0x70d638), inventory changes `0x45/0x46` (four 4-byte fields + a JSON blob), rating `0x37`, alias
  `0x70`, JSON events (`0x0d`, `0x3c`, `0x3d`, `0x65`, `0x77`, `0x83`, ...), and the **integrity request `0x3a`**, which
  makes the client answer with `0x3b` (`GetImgCs` digest). Our TS simply never sends `0x3a` [V]. Events are queued
  (G:0xd0b640) and handled by type in G:0xd05e50 [V].
* **Client → server:** 110 builders for 95 message types around G:0xcf2000-0xcf8b10 and G:0xd08000-0xd10d10 (catalog) [V]. Their
  meaning (mission start/finish, purchases, upgrades, rewards, social) must be read one by one from their callers;
  that is M1 work, starting with what the campaign uses.

**Economy:** the TS sends inventory changes and config, so prices and rewards live in data we must supply. The
balancing tables are expected in the game data (asset packs); M1 needs a private copy of your asset-pack backup to
read them.

## 4. Federation requests

The generated table lists 68 builders. Highlights [V]:

* eve: `GET /config/{client_id}/datacenters` (`country`), `.../datacenters/{dc}/urls`; pandora `/locate` with
  `service`; the `http://` → `https://` rewrite of `pandora` and `federation` (G:0xd85db0/G:0xd86020).
* auth: the user-token builders G:0xd8fd48/G:0xd91368 send `client_id username password device_id scope
  for_username for_credential_type custom_token_duration [access_token_only]`; refresh with `grant_type`
  (G:0xd959c8); `/users/me`, `/users/me/transfer_code`, `/games/mygame/alias`, `/get_third_party_auth_token`;
  `/sessions/` with `client_id credential password device_id`.
* CRM: `/configs/users/me` with `etag`, `profile_name`, `selector`, `now`, `If-None-Match` (G:0xd8b1d0).
* assets (Iris): `/assets/{client}/{asset_name}` with `etag`, ranges `from_offset`/`to_offset` (the BALD DLC),
  `/metadata`, `/metadata/hash`.
* matchmaker: `/rooms/` with `server_type`, `/automatch/` (score ranges, `instant`, team rooms), `/quick_join`.
* social, groups, Hermes, Kairos alerts, leaderboards, wall, events, gifts, IAP and subscriptions: see the table.

Response fields per endpoint: next step, driven by the M0 device log (every request is logged with full detail) and
the response parsers.

## 5. Match authority and bots

* **Symmetric protocol:** the client builds 221 distinct in-match message types (G:0xbc8000-0xbe0800) and its
  receive dispatcher G:0xbe5fd8 handles the same range, `0x0b`-`0xe7`, in 221 cases (Ghidra needs a 20-minute
  timeout for it) [V]: clients send the messages they also receive.
* **Authority role:** G:0xbc02c0 tests a byte flag of the match session; 361 functions call it [V]. When it is set,
  a received message from another player is re-serialised to one of two outgoing streams, skipping the sender
  (G:0xc1a778) [V], and the role holder makes the decisions: for example a zone capture plays locally everywhere but
  only the role holder sends message `0x3d` with zone and team (G:0x7fd0d8 → G:0xc24098) [V]. Role-gated code covers
  captures, flags, pickups (ammo, health, armour), death, health boxes, hit reactions (`hitType`, `eventHit`),
  killstreaks, zombie spawns, sudden death and end-of-match results [V].
* The Lua `IsServer()` binding always returns false in this build (G:0x8c9628) [V]; the role flag is separate.
* **Bots:** the client's bot manager (G:0xc41a80, called by G:0xc083a8 when bot counts are set) adds and removes bot
  players, each with a `bot_credentials_%d` identity (G:0xc42270) [V]. Bots are simulated by a client [L].
* **Open:** where the role flag is set (which message or room field) and what the GS itself did besides relaying
  (join/leave, timers, results). These are M2 tasks.

**For us:** the GS does not need its own simulation. It is the Anubis controller plus a relay and the room/match
lifecycle; one client (the host phone, or the only player in a bot match) holds the authority role and runs the
rules and the bots. This is much smaller than the estimate in 00-recon §3.3 [L until the role assignment is found].

## 6. Changes to the plan

* **M0** unchanged.
* **M1 (offline campaign)** now explicitly includes the **TS**: `ClientSendInitSettings`, the profile document
  (owned, stored and sent by us), config (empty first, since the client accepts it), and the client→server requests
  the campaign uses, with responses built from the game's own tables.
* **M2 (bot matches)**: GS = Anubis controller + relay + room lifecycle; the local client holds the authority role
  and runs the bots.
* **Needed from you for M1:** the asset-pack backup, shared privately (not in this public repository), so the
  economy tables and data formats can be read.
