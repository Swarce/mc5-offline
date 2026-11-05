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

## 7. Popup root cause — legislation/compliancy never initialized (2026-11-04, `mc5-popup-rootcause` workflow + manual verify)

Status: **[V]** mechanism verified against the real `libMC5.so` (string-xref addresses are REAL
file vaddrs via `tools/re/xref.py`, no decomp shift) and the on-device logs `12d721fe`/`7beb5d7f`
(new build) + `a10018bd` (raw logcat).

**Symptom chain:** the whole fed session completes (eve→pandora→auth→alerts SSE→users/me→
behavioral.json 99B→social persisted→message→encrypt_token, no reloop), then a generic
connection-error popup — instead of the first-run age/gender screen. Game-native log (tag `MC5`,
*not* suppressed): `log-brazil : legislationVersion:` **empty**.

**Root cause:** the client never fetches `compliancy.json`, so the Restrictions/legislation
config stays uninitialized (`GetLegislationVersion 0x13d3538` reads `Restrictions+0x178` == null →
`JSON_NOT_INITIALIZED`). `compliancy.json` and `behavioral.json` use the SAME IRIS asset engine
(`store GetAsset 0x1385430`, URL `https://eve.gameloft.com` @0x14ad840) but via two providers with
opposite policies:
- **behavioral.json** — owned by an ACTIVE manager (`BehavioralMgr IRIS-Init 0x137e570`, hardcodes
  `'behavioral.json'` @0x14a7a66, sole caller of fetch `0x1387730`). Self-downloads at boot. ✓ seen.
- **compliancy.json** — owned by a PASSIVE adapter. Its only network path is vtable **slot4**
  (`0x13b9d68`, sole referencer of `'compliancy.json'` @0x14a79d4 → `0x1385430`). `calls.py 0x13b9d68`
  = **0 BL callers** → dispatched by vtable only, and nothing dispatches it pre-profile. Never seen.

**Verified caller graph (`tools/re/calls.py`):**
- `0x1385430` (fetch engine) ← exactly `{0x137e9c0 behavioral, 0x13b9d68 compliancy-slot4}`.
- `ProcessCompliancy 0x13961e8` ← only `0xbcdab0` (login FSM state 5, handler `0xbcdd10`).
- `Restrictions::Init 0x13c56c0` ← only `0x13961e8`.
- `RequestRestrictions 0x13a20b0` (the only thing that dispatches compliancy slot4, via the update
  thread `0x13cb580`) ← 7 funcs incl. `AgeValidator 0x13df5a8`; all post-age-entry.
- At boot, `ProcessCompliancy` calls legislation loader `0x13d6fd8` (NOT a caller of `0x1385430` →
  cache-read only) + `EnsureCompliancyLoaded 0x1395260` (provider slot3 = `HasCachedConfig 0x1384f68`,
  local read). Neither network-fetches. Flags: `IsLegislationInitialized` reads `Restrictions+0x218`
  (atomic, `0x1396c98`); a separate `Restrictions+0x100` (reader `0x109cdb8`) gates `Init`'s full branch.

**The login FSM is NON-FATAL on this** (`0xbcdab0` state 5 `0xbcdd10`): it filters
`ProcessCompliancy` ret (`w19==0` or `==0x29` both skip; else only stores a `'compliancy error %d'`
telemetry string) and unconditionally advances to state 7. So the popup is raised by a **downstream
consumer** of the unresolved restrictions state — **NOT yet isolated**.

**Eliminations:** popup is NOT a Gaia result code (setter `0xc35cf8` tee silent on-device, all ops
200), NOT the restricted-mode signal `0x389` (emission at `0x13d0810` gated by `0x13d0368 cbz` on
`Restrictions+0x178`, so it can't fire while legislation is null).

**Open (blocks the fix choice):**
- The exact front-end branch (likely Lua/UI) that shows the popup vs the age/gender screen.
- Under what precondition a healthy client dispatches compliancy slot4 at/near boot (is `+0x100`
  config/response-driven? does a richer behavioral.json or a legislation-version field trigger it?).
- Whether seeding the encrypted on-device IRIS cache (so `HasCachedConfig` succeeds) is sufficient.

**Candidate fixes (ranked by project fit; none applied yet):**
1. Find a server/response lever that makes the stock client fetch `compliancy.json` on its own
   (cleanest; aligns with "reimplement from the client's own code, minimal patching"). Unproven it exists.
2. Native hook to force the fetch/early `RequestRestrictions(country=CA, adult age)` so the existing
   path populates `+0x178` (medium risk; needs valid object ptrs/args).
3. Seed the encrypted IRIS cache with the compliancy JSON (needs matching the game's cache crypto).
4. Patch the legislation gate directly (riskiest; `+0x178`/`+0x218`).
Server already serves a valid `compliancy.json` (asset.cpp) — necessary once the fetch is forced, but
inert until something requests it.

## 8. Popup is NOT legislation — it is a post-login re-login loop (2026-11-04, trace round 2)

Status: **[V]** on-device entry traces (build `ab99acf`, logs `d1d16442`/`9178133b`).

Round 1's §7 legislation theory is **DISPROVEN by instrumentation**:
- `trace: RestrictionsInit this=.. +0x100=0x0 +0x178=0xb4..ec90 +0x218=0x0` then
  `trace: GetLegislationVersion .. +0x178=0xb4..ec90 +0x218=0x1` — the legislation JSON
  pointer (+0x178) is **non-null** and the init flag (+0x218) is **set**. Legislation
  initialises fine. The boot `LegislationLoader 0x13d6fd8` runs (lr=+0x1396314) and
  populates +0x178. The empty `legislationVersion` string is therefore **benign**.
- `ComplianceFetch(slot4) 0x13b9d68`, `RequestRestrictions 0x13a20b0` and the
  restricted-mode signal `0x13d02e8` **never fire** — so restrictions never errors and
  the "restricted mode" popup theory is out.
- No Gaia result code is set (0xc35cf8 silent) — confirmed again.

**Real symptom:** after the HTTP login chain fully succeeds (all 200), the game does a
full re-login (`POST /auth/authorize` scope `tracking_bi` then full scope, fresh
users/me, social, encrypt_token) **every ~12–15s**. The OnlineFramework tears down and
restarts the online session. The expected age/gender screen is the age gate, which runs
via `RequestRestrictions` — and that never fires, consistent with the session never
reaching "online ready".

**Gaia → Lua login bridge (string xref):** the online layer drives the UI through three
callbacks — `onLoginCompleted` (emitter `0x1354158`), `onLoginFailed` (emitter
`0x1354418`, error code in `w2`), `onDisconnected` (emitter `0x1353fb8`). All three are
vtable-dispatched state handlers (0 direct callers). `onLoginFailed` is fired by the
login-failed state entry `0xbb96e8` (notifies observers with code 2, sets flag
`+0x17c=1`). `StartLogin 0xbcd410` has 6 callers (initial + retry paths); the outer
dispatcher `0xbcd660` (phase field `+0x3dc`) and per-frame tick `0xc184f8` pump it.

**Open:** which of onLoginCompleted / onLoginFailed(code) / onDisconnected fires after
the chain, and what re-triggers StartLogin — trace round 3 (build `41d9647`, hooks on
those four) will answer. Leading hypothesis: a post-login timeout waiting for a
real-time "connected" confirmation (the alert/presence stream only receives SSE
*comments* from us, never a real `connection` event), producing onLoginFailed/
onDisconnected → the connection-error popup → retry.

## 9. Confirmed: login FSM stalls post-HTTP; no terminal callback; Lua retries ~1/s (trace round 3)

Status: **[V]** on-device (build `41d9647`/`89f79df`, logs `15499c18`, `1ce09c22`).

With the login-event hooks working (after fixing a trampoline pad bug, `89f79df`), a long
capture shows the loop unambiguously:
- `StartLogin x1=0` from the OnlineFramework (`+0x833404`) = silent/BI phase.
- `StartLogin x1=2` from the **Lua dispatcher** `0x8f4e40` (`+0x8fc7d8`) = the real login,
  then repeated **once per second** (:05,:06,:07,:08…).
- Every cycle runs the FULL HTTP chain (authorize→alert SSE→users/me→behavioral→
  encrypt_token→social locates→`POST social/accounts/me`), **all 200**.
- **None** of `onLoginCompleted` (`0x1354158`) / `onLoginFailed` (`0x1354418`) /
  `onDisconnected` (`0x1353fb8`) EVER fire. Verified by entry hooks that patch the
  function entry, so any call (incl. vtable `blr`) would log. `onLoginCompleted` and
  `onDisconnected` have **no BL/B callers** at all (pure vtable dispatch); only
  `onLoginFailed` is called directly (by the failed-state handler `0xbb96e8`).

**Conclusion:** the Gaia login state machine completes the HTTP chain but never reaches
the state that fires `onLoginCompleted`; the Lua login screen, never told the result,
re-calls `StartLogin` ~1/s → the connection-error/retry loop. The stall is NOT an HTTP
request/response (all 200) — it waits on something else after the chain (leading
candidates: a real-time presence/"connection" event on the alert SSE stream — we send
only SSE *comments*; or a subsystem readiness signal; or the TS/lobby connection).

Round 4 (build `e8b6eb7`) hooks the FSM pump `0xbcdab0` and logs the state global
`0x1bc434c` on change (`fsm-state: N`) to pinpoint the stall state (map: state 5 =
compliancy, 9 ≈ terminal). `SetState 0xbcd600` is unhookable (two leading adrp, 24-byte
leaf), so the pump is traced instead.

## 10. ROOT CAUSE: login "connected" gate (obj+0xEC) never set → popupConnectionLost

Status: **[V]** on-device FSM trace (build `e8b6eb7`, log `efa072b7`) + static RE.

Full FSM state sequence of a complete login cycle: `2→3→4→6→5→7→8→11` then rests at
**state 11** idle (no re-login, no terminal callback) — the auth FSM finishes but login
never reports success. Jump table @`0x15f92d0` confirmed; state 9 (`0xbcdf74`) is the
SUCCESS terminal, state 11 (`0xbcdba8`) is the stuck rest state.

The branch is in the **state-8 handler** (`0xbce054`):
```
bl 0x707ec0            ; gate(): return *(bool*)(gateObj+0xEC)
tbz w0,#0,#0xbce3a0    ; if 0 -> branch B -> SetState(11)   [stuck]
... fall through -> 0xbce0c4: mov w0,#9; SetState(9)        [success -> onLoginCompleted]
```
Gate `0x707ec0` = `ldrb w0,[x0,#0xec]; ret` (gateObj = `*(0x4e46a0() + 0x1b8)`). On our
setup `+0xEC==0`, so login diverts to state 11 and the Lua dispatcher `0x8f4e40` shows
**`popupConnectionLost`** (string `0x14812b1`) and re-calls `StartLogin` ~1/s.

The flag is set by `0x707a90(obj, w1, w2)` (`+0xEC=1` iff `w1==0 && w2!=0`), called only
by the event handler **`0xb00508`** when a connection message with `msg[0xe]==0 &&
msg[0xf]!=0` arrives (msg fields: `+0xa` u16, `+0xc` s16, `+0xe` u8, `+0xf` u8). This is
the server-pushed "online session established" event that real Gaia delivers and our
loopback does not — so the flag never sets.

**Fix chosen (user): server-side.** Deliver the connection event (expected: a real event
on the alerts/me SSE stream, which is subscribed to alert_types incl. `connection`) so the
client sets `+0xEC` itself. Next: pin the alert "connection" event wire format (SSE
event name + data → the `msg[0xe]/0xf` fields) and emit it from `server/services/alert.cpp`.
Gate getter `0x707ec0` has 8 callers (login FSM + ~7 online-state checks), so a patch
would be broad; the event path sets the real flag consistently.

## 11. Gate patch result: popup GONE, now past login into a black menu screen (build 55aa4dd)

Status: **[V]** on-device (log `a25299b4`/`d19de46f`).

The connected-gate patch (`0x707ec0` -> `mov w0,#1`) works at the FSM level: the login
FSM now reaches **state 9** (success terminal) instead of the stuck state 11, and
`popupConnectionLost` is **gone**. The game advances into a NEW phase never seen before:
`POST /auth/authorize scope='config storage_ro'`, `HEAD/GET .../use_custom_param`,
`.../videos_HD_UPD18(+/metadata/hash)`, `.../events_HD_UPD18(+/metadata/hash)` — i.e.
menu config/content loading.

Remaining issue: `onLoginCompleted` (`0x1354158`) still never fires — reaching FSM
state 9 does NOT fire it (it's a separate OnlineFramework delegate vtable call, slot 1 of
vtable `0x1b90c28`). The Lua dispatcher `0x8f4e40` re-calls `StartLogin(2)` ~8× in 7s
(21:22:26→33) then **stops**; afterwards the game is idle on a **black screen** (watchdog
only, no requests). Rendering is fine (Vulkan, frames composited) — it's a content/UI
state, not a render crash. Content assets (`use_custom_param`, `videos_HD_UPD18`,
`events_HD_UPD18`) are currently served by the catch-all (empty/minimal).

Open: (a) does onLoginCompleted need to fire for the menu, or did login settle? (b) is the
black screen the age/gender first-run UI with no content, or a stuck menu? Next: identify
what the post-login menu/first-run screen needs (content assets and/or the login-latch).

## 12. The real popup trigger: network-session connection slot 0 not CONNECTED

Status: **[V]** static RE (runtime confirmation pending, build `4ddf4cd`).

Runtime round 5 showed the connection-state handler `0xb00508` (only setter of +0xEC)
**never fires**. The "login listener" vtable `0x1b90c28` turned out to be the Vivox
voice-chat listener (onConnectCompleted/onConnectFailed/onDisconnected/onLoginCompleted/
onInvalidLoginCredentials/onLoginFailed/onLogoutCompleted/onLogoutFailed/
onChannelJoined; Vivox SIP/channel code in `0xbb9xxx`) — not the account login.

`popupConnectionLost` is *opened by the SWF*; native `0x8f4e40` is the SWF button
dispatcher (by popup name). Its OK action (`0x8f76f0`) sets the front-end manager
(`m = 0x4e2108()`) state `m+0xB454 = 2`, clears `m+0xB45C` — that state drives the
`StartLogin(x1=2)` retries. The front-end per-frame check **`0xb30438`** enters
"connection lost" via **`0xb30d80`** (sets `m+0xB454 = 1`) when:
```
conn = m->+0x10
lost = !conn || ( conn->u8[0x6c] == 0  &&  conn->i32[0x98 + 4*0] != 2 )
```
i.e. **slot 0 of the network-session connection table is not CONNECTED (2)**. Slot
handles at `conn+0x90+8*i`, states at `conn+0x98+4*i`; set by `0x8cc370` (→1
connecting) and `0x8cc3b0` (→2 connected). Paths: `0x8cc228` (local: connecting then
connected immediately) and `0xae5928 → 0x8ccdf0` (remote asio connect + handshake).
Not the cause: `isConnectionOK` (= `acp_utils::PackageUtils::GetConnectionType`, device
network type) → only drives the separate `noWifiPopup`.

Next: confirm on-device which path runs and slot-0's state at the popup, then make that
connection actually reach CONNECTED (server-side if it's a socket to our loopback).

## 13. The popup decoded: login error string → "Failed to connect!" (first cause: `_datacenter_id`)

Status: **[V]** static RE + device log `7ca96683` (build `89f79df`+); fix pending on-device.

**Where the text comes from.** The two popups the player sees are native strings from the
encrypted `strings.gla2` (decoder: `tools/re/gla2.py`, cipher reimplemented from
`0xbbd2b0`, seed `0x3857a`; a language pack is NUL-separated strings whose ordinal is the
id passed to GetString `0x8eec38`/`0x841f38`): id **1733** "Failed to connect! Please check
your Internet connection and try again." and id **1942** "Servers are temporarily
overloaded. Please try again later." (1938 = "No Internet connection available…").

**Who shows it.** `loginMMError` `0x831fd0`, called from the game state machine `0x82ea48`
(`0x830f98`, `0x831100`) whenever the global login-error `std::string` @`0x1bc4360`
(checked by `0x831f58`) is non-empty:
```
code == "glni"            -> id 1938 (no internet)
online+0x438 == 2         -> id 1942 (overloaded), counter reset
else                      -> id 1733 (failed to connect), counter++
```
So "overloaded" is **not** a server condition — it is the same failure on every 3rd retry.

**Who sets the code.** Only `SetLoginError` `0xbcd618` (16-byte leaf → `std::string::assign`
`0x40b838`), from the Gaia login FSM. Codes: `glrer_<type>_<code>_<msg>` (`0xbd1518`),
`glrec` (state 2), `gluvr` (state 10), `compliancy error %d` (state 5), `glgc_%d`,
`gltv/glte/gltewc_%d_%d` (state 12, 180 s timeouts), and `gl<…>` / `gldah{d,b,v,np}` from
the state-8 gate-false path (after 3 pumps or a flag) → state 11.

**First failure (every launch): the dataCenter re-check.** On `StartLogin(0)` with a stored
session, state 2 (`0xbcdb00`) calls `0xbcf430`: a Gaia request keyed **`"dataCenter"`**
(static string char-built at `0x35c1b0`, XOR-0xf5) with callback `0xbd1518`; FSM → state 0.
The device log shows exactly one request, `GET /config/{cid}/datacenters?country=CA -> 200`,
then state 11 18 ms later. The callback sees a non-zero result code and sets
`glrer_…`. Cause: the Gaia DataCenter deserializer `0xca8ed8` requires the string fields
`name`, `status`, **`_datacenter_id`** and bool `preferred` (`country_code` optional); a
missing field returns −24. Our eve reply had no `_datacenter_id`. The retry (`StartLogin(2)`)
happened to skip that call (cached dc) and ran the full chain `3→4→6→5→7→8`.

**Fix (server, clean):** `server/services/eve.cpp` now returns
`"_datacenter_id": <dc name>` in each datacenter entry.

**Second failure (retry path): state 8.** With the gate `+0xEC` false (§10), state 8 sets a
`gl<…>` code and goes to state 11 → popup again. §11's gate patch reached state 9 but the
player still saw the popup over a black screen — consistent with the *first* failure
(`glrer`, every StartLogin) still firing, which this section explains.

**Diagnostics added:** `install_login_error_hook()` replaces `SetLoginError` with a logger
(`login-error: SetLoginError("<code>") caller=+0x…`) that then performs the original
assignment, so the next run names every remaining login error exactly.

## 14. Device round 4d2aeda: datacenter fixed; two remaining codes decoded

Status: **[V]** device log `b349c322`/`bba41ee8` + static RE (workflow: 3 investigations,
each adversarially verified; key claims re-checked by hand).

The `_datacenter_id` fix worked: the first login now runs `2→0→3→4→6→5→7→8` (no `glrer`).
The SetLoginError hook names the two remaining codes, identical on every attempt:

**A. `compliancy error 28` (state 5, caller `0xbcded8`) — poisoned on-device cache.**
State 5 calls ProcessCompliancy `0x13961e8` → Restrictions::Init `0x13c56c0`, which first
checks the encrypted cache `compliancy.bin` (`0x1389e18` → `0x138c130`, name char-built).
On 11-04 an early build's catch-all answered `compliancy.json` with `{}`; the client caches
the reply *before* validating it (CacheConfigJson `0x138a930`). `{}` is a valid JSON
object, so every later login takes the cache, never fetches our (valid) compliancy.json
(no request for it in any later log), and ParseConfigJson `0x138d9f8` fails "Missing
LegislationTypes" → 0x1c = 28. The only deleter (Reset `0x1394020`) runs only after a
successful parse, so it never self-heals. State 5 still always proceeds to state 7, but the
error string is cleared only by StartLogin — nothing on the success path clears it — so it
would raise the popup even after a state-9 success (the gate-patched build `d19de46f`
reached state 9 six times and each was followed by the popup → StartLogin(2)).
**Fix:** `diag.cpp` deletes `compliancy.bin` at boot (with fed_links/`*_cache.bin`);
compliancy.json additionally carries `"StoreType":["google"]` (hardening against the
unresolved `0x1390e48("20.0.0", LegislationVersion)` direction).

**B. `gl` (state 8, caller `0xbce584`) — the game_portal/Anubis connection never starts.**
Correction to §10/§12: `gateObj = *(app+0x1b8)` is the **game_portal "Anubis" manager**
(ctor `0xc05610`, vtable `0x1b0b230`, "Anubis Manager Thread", TCP handler `0xc09780`:
TCP_Profile/TCP_Config/TCP_LVLFile/…) — i.e. the TS meta channel of 01-phase1b §3.
`+0xEC` ("controller session established") is set only by `0xc05870` from the Anubis FSM
`0xc071d8` (state global `0x1bc5834`) state 10 (`0xc07754`) once flags `+0xb0,b1,b3,b4`
are set by TCP messages 0x22, 0x3e/0x3f (TCP_Config), 0x4a and connection event 2. The
earlier `0x707a90`/`0xb00508` attribution was an ICF artifact (in-match entity component).
State 8 (`0xbce054`): waits only while `+0x94>0` (Anubis attempt running); gate `+0xEC` →
state 9; else `counter(0x1bc43c8)++` and retry `0xc07020`; on the 4th pump
`SetLoginError("gl"+suffix 0x1bc5840)` → state 11. `0xc07020` looks up **`"game_portal"`**
in the eve urls object; ours omits it (removed in 4e4a65e on a mistaken "1 KB parser"
theory), so nothing starts, the suffix stays empty, and "gl" fires within one second. The
`gldah*` strings built on that path are dead (never passed on). Don't patch the getter
`0x707ec0`: it is ICF-shared by 8 functions (vertex-attribute count, loop bounds, entity
highlight…), which may explain the old black screen.

Options for B: (1) **real fix** = M1 meta channel: add `game_portal` to eve urls, serve the
Anubis state-3 request (`quick_join_ah`, `server_type=ts` → `room_id`, `controller_host`,
`controller_tcp_port`, `encrypted_access_token`), run the Anubis controller + TS on
loopback and send 0x22 / 0x3e TCP_Config / 0x4a / event 2 / TCP_Profile within the Anubis
and login-wide (`online+0x254`, 180 s) timeouts; partial progress shows up as
`gl<code>` (`glaca`, `glavct`, `glatg_<st>_<ms>_D_<b0><b3><b1><b4>`). (2) **stopgap** =
call-site patch at `0xbce06c` `bl 0x707ec0` (`95 e7 ec 97`) → `mov w0,#1` (`20 00 80 52`),
with game_portal kept out; reaches state 9 but delivers no profile.
