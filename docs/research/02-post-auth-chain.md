# 02 — MC5 post-auth boot-to-menu chain (map + gap analysis)

Status: **[V]** verified against the shipped arm64 `libMC5.so` decompilation, our server
source, the MCVS reference, and the on-device trace of 2026-11-04 (logs `6af3a124` /
`6b513028`). Produced by the `mc5-post-auth-map` workflow (5 agents). Addresses in the
decomp's `0x148xxxx` range are shifted ~+0x100000 from the real library — rely on string
xrefs, not raw addresses (see §0).

## 0. What already works on device (2026-11-04)

After dropping the two misidentified "scheme-rewriter" patches and adding `"status":"none"`
to eve urls, the client now gets through, in order:

```
GET  /config/{cid}/datacenters                -> 200 (71 B)
GET  /config/{cid}/datacenters/eur/urls       -> 200 (217 B, status:none + pandora/federation/ecomm_api_root/crm_iap)
GET  /pandora//locate?service=asset           -> 200 (base URL text)
GET  /pandora//locate?service=auth            -> 200
HEAD + GET /asset//assets/{cid}/GameOptions   -> 200
POST /auth//authorize (credential=anonymous:<b64 GLUID>, scope=tracking_bi) -> 200 {access_token,scope}
```

This is the **ETS/BI telemetry side-channel** (GaiaManager) plus the **asset/Iris** path —
both non-blocking. The capture then **backgrounded ~8 s later** (intro video finalized
10:14:19, `WindowStopped`/`surfaceDestroyed` 10:14:23), **before the main game session
started**. The main `authorize` fires only *after the user taps past the title/consent gate*.
So the first post-`tracking_bi` break point is **not yet confirmed by trace** — needs a
foregrounded capture that taps through.

On-screen: the same Gaia `0x1d` "connection error" popup; the expected next screen is
**age/gender selection** (first-run profile creation), which depends on the profile that is
delivered **only over the TS meta-channel** (§4).

## 1. Remaining HTTP chain (to implement, in order)

| # | call | our status | required response | priority |
|---|------|-----------|-------------------|----------|
| 1 | `POST auth//authorize` main scopes `alert auth leaderboard_ro lobby message social chat session` | partial | `{access_token, scope:<echo verbatim>, token_type:"bearer", expires_in:31536000}` | blocker |
| 2 | `GET auth//users/me?access_token=` | partial | `{"account":"<24hex,no colon>","credentials":["anonymous:<GLUID>"],"client_id":"1924:56128:6.0.12a:android:googleplay"}` | soon |
| 3 | `POST auth//games/mygame/alias` | stub(catchall) | `{"alias":"<9 digits>"}` (deterministic from account) | soon |
| 4 | `GET config//configs/users/me` (+selector, `If-None-Match`) | stub(catchall) | real **CRM document**: `{"iap":{"prices":[]}, ...flags}`, no age-gate / mandatory-update | **blocker (likely next stall)** |
| 5 | `GET ecomm_api_root//android/banned_services/` | stub | `[]` | soon |
| 6 | `GET ecomm_api_root//purchases/?get_non_consumables=` | stub | `{"non_consumables":[]}` | soon |
| 7 | `GET crm_iap//subscriptions/?verify_subscription=` | stub | `{"subscriptions":[]}` | soon |
| 8 | `GET alert//alerts/me` | stub | event stream (held open); empty OK | later |
| 9 | `POST matchmaker//rooms/{cid}/quick_join_ah` (`server_type=ts`) | stub(catchall = blocker) | `{room_id, controller_host:"127.0.0.1", controller_tcp_port:<n>, encrypted_access_token:<echo>}` | **blocker** |

### auth hardening (session agent, high confidence)
- **account-id consistency (potential desync blocker):** tracking sends one field
  `credential=anonymous:<GLUID>`; the main-session builder `FUN_00d18d80` sends **separate**
  `accountType` + `username`. `auth.cpp::requested_credential()` reads `username` first, so the
  two paths derive **different** `account = sha1(...)[:24]`, desyncing users/me/verify/TS.
  **Fix:** when `accountType`/`credential_type` + `username` are both present, compose
  `"<type>:<username>"` before `account_for()`.
- **users/me:** credentials must be an **array of `type:username` strings**, not objects;
  `account` must contain no `:`; include `client_id`.
- **401 semantics:** unknown/parse-failed token on a token-bearing request → **401** (client
  drops tokens, re-authorizes once); never 403/404. `authorize` itself never 401 for anonymous.

### storage: do NOT implement
MC5's native client **never calls the Gaia storage service** for its own profile (zero
`profiles/me`, `data/{cred}/{key}`, `get_profile` builders in the decomp). Leave the `{}`
catch-all. The profile load/save is the TS channel (§4).

## 2. CRM config document (§4 call) — shape
Port MCVS `content.md` CrmDocumentBuilder: a JSON object served for any token/selector
(`/{*selector}` → sub-tree, never 404), minimally an `iap` object so the native IAP callback
fires, plus flags that disable popups (no `mandatory_update`, `age_gate`, `maintenance`).

## 3. matchmaker quick_join_ah — the TS locator
`POST matchmaker//rooms/{cid}/quick_join_ah` with `server_type=ts` (decomp `G:0xd071d8`) must
return `room_id`, `controller_host`, `controller_tcp_port`, `encrypted_access_token`. The
`connect()` hook rewrites the port to 51780 regardless, so `controller_host=127.0.0.1` +
any port works. The current `{}` catch-all lacks these fields → client never opens the TS.

## 4. TS / meta-channel (the real remaining blocker) — **non-HTTP**

The **player profile/save lives only on the TS**, a persistent binary-framed TCP channel,
not an HTTP service. Reached in three stacked stages on one socket:

**(A) Anubis controller** — newline-delimited JSON over TCP (decomp `00d3.c`):
```
server->client  {action:"create connection", nonce:...}
client->server  {action:"login", access_token:<encrypted_access_token from quick_join_ah>, <RoomUser fields>}
client->server  {action:"connect game", room_id, username, nonce_type}
server->client  <slot reply>
```
Sockets are asio-managed with `SO_KEEPALIVE`/`TCP_KEEPIDLE`; there is an app-level heartbeat —
keep the socket alive.

**(B) TS binary meta-protocol** (same socket, after `connect game`):
- **Framing:** `[type:u8 (0x01..0xAD)][length:u16 BIG-ENDIAN, INCLUDES the 3-byte header][payload]`.
  256 KB rx buffer, exactly one message per callback. Frame itself not encrypted/compressed.
- **Payload primitives (BIG-ENDIAN):** u8/u16/u32/u64, f32/f64; `str`=u16 len+bytes;
  `bytes16/bytes32`=u16/u32 len+bytes; `blob32`=u32 len+bytes; `lz4blob`=u32 len + LZ4 block
  (decompresses to ≤1 MB NUL-terminated text; LZ4 at `G:0x5dfff0`).
- **Pair rule:** the lower type of a pair carries the blob PLAIN, the higher carries it
  LZ4-compressed (`0x03` plain / `0x27` compressed profile, etc.).
- **Client->server first:** `0x01` **ClientSendInitSettings** (builders `G:0xcf2660`/`G:0xd08008`):
  `u8 0x33, u8 0x0b(ver), u32`, then a run of strings starting with the client's **pandora URL**,
  then credential / access token / device id, flags. (tcp-messages.md 0x01 layout.)
- **Server->client minimum to clear the menu hang:**
  - `0x3e` **config** (`lz4blob + 2×blob32`) — **may be empty**, client applies a default via `G:0x70d638`.
  - `0x03`/`0x27` **TCP_Profile** (`lz4blob + blob32`) — the player save as JSON (keys per
    `01-phase1b.md §2`: credits, rd_currency, rating, statistics, campaign m_progress/ev_chapters/
    m_challengesProgress, inventory/_inventory_shadow, alias, created, gender, …). Use **plain `0x03`**
    first to avoid wiring LZ4.
  - then `0x45`/`0x46` inventory and `0x04`/`0x28` tournaments (may be empty).
- **INTEGRITY:** server->client `0x3a` requests a digest; **our TS must NEVER send `0x3a`**.
- **Do not conflate** with the in-match replication channel (dispatcher `G:0xbe5fd8`, ~221 types,
  reached via a different `quick_join_ah server_type=ahgameserver`).

### Our-server gap
The `connect()` hook already funnels the TS socket to `127.0.0.1:51780`, but the listener is
HTTP-only. **Multiplex:** peek first bytes — HTTP verb → existing Router; else → Anubis (newline
JSON), then after `connect game` hand the socket to a TS binary framer.

## 5. Implementation priority to reach the menu
1. (HTTP, cheap) authorize hardening + users/me shape + alias + CRM `configs/users/me` + ecomm/iap empties.
2. (HTTP) matchmaker `quick_join_ah(ts)` real response.
3. (core) loopback protocol multiplex: sniff HTTP vs non-HTTP.
4. (TCP) Anubis handshake (`create connection`/`login`/`connect game`).
5. (TCP) TS binary framer + push `0x3e` empty config + `0x03` default TCP_Profile; never `0x3a`; keep-alive.
Everything beyond (full economy, tournaments, client->server handlers, saves) is M1.

## 6. Open questions (need a foregrounded capture / first TS frame)
- Exact first break after `tracking_bi` (main authorize? `configs/users/me`? matchmaker?) — the
  last capture backgrounded before the main session; foreground + tap past the title to confirm.
- Exact `0x01` ClientSendInitSettings field order (credential vs token vs device id).
- Whether an **empty/minimal** TCP_Profile reaches the menu or specific keys (`created`, `alias`,
  `gender`) are required by the loader `G:0x6e1498`.
- Heartbeat framing / whether the client needs periodic server keepalives vs only SO_KEEPALIVE.
- Whether the Anubis/TS side re-verifies `encrypted_access_token` or accepts any opaque token.
