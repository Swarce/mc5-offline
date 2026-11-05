<!-- Produced by the mc5-m1-anubis-ts-spec workflow (4 RE areas, each adversarially verified, then a spec pass), 2026-11-05; key claims re-checked by hand (see 02 §15). Addresses are libMC5 6.0.12a arm64 ELF vaddrs. -->

# Implementation spec: Anubis controller and TS meta channel, from login state 4 to gateObj+0xEC=1

Addresses are ELF vaddrs. Ghidra address = ELF + 0x100000.

**What has to change, in short:**
- Add `game_portal` to the eve urls.
- Answer the client's Federation `POST …/sessions/…` request with the four controller keys.
- Add `"success":true` to both controller JSON replies.
- Send no binary until the client's first TS frame arrives. Then send four frames: 0x22, 0x3e, 0x04 and 0x4a.
- After that, send a 3-byte no-op frame every 5 s and never close the socket.

**Before testing:**
1. Commit f3b8e47 (the compliancy-28 fix) must be in the build. Otherwise the popup appears even when this chain succeeds (02-post-auth-chain §14.A).
2. Kill the app process between test runs. The mode flag `0x1bc586c` and `gateObj+0xb4` survive retries inside one process.

---

## 1. End-to-end sequence

### 1.1 Timeline (happy path, mode 0 "targeted")

| # | Who | What | Client state after |
|---|---|---|---|
| 0 | C | Login state 4 (`0xbcdc30`) calls `0xc07020(gate, client_id)`. It reads eve `game_portal` with `0xc86e18`; the value must be a non-empty JSON string. It sets `+0xe8=now` (starts the 60 s Anubis clock), starts the "Anubis Manager Thread", sets `+0x94=1`, clears the suffix, and sets FSM `0x1bc5834=2`. | Anubis S2 |
| 1 | C | S2: `0x1bc583c` is 1 on the first start, so S3. In S3 the mode check calls `ca5428` with serviceName "federation". That name is not in the pandora list, so it is looked up synchronously in eve. Found as a string → code 0 → mode 0. | S3 |
| 2 | C→S HTTP | `POST <eve federation url>/sessions/<urlenc client_id>/<urlenc credential>`, form body `password=…&device_id=…` (request type 0x1902). | S1, op 3 |
| 3 | S→C HTTP | `200` with a JSON object carrying the four controller keys (§2.2). | S4 → S5 |
| 4 | C | S5: lobby op 0x11 does a blocking `getaddrinfo/socket/connect(controller_host, controller_tcp_port)`. Our hook redirects it to our port. The client sends nothing first. | CC state 2 |
| 5 | S→C TCP | `{"action":"create connection","nonce":"mc5offline","success":true}\n` | CC 3, S8 |
| 6 | C→S TCP | `{"access_token":"<token>","action":"connect game","nonce_type":"targeted","room_id":"<id>","username":"anonymous:<…>"}\n` | CC 0xa |
| 7 | S→C TCP | `{"action":"connect game","slot":"0","success":true}\n`, and **nothing after it** | CC 0xb. The callback sets `+0x58=1` (TS reader on) and moves to S9. |
| 8 | C→S TS | Frame `0x01` ClientSendInitSettings, then `49 00 03` (sent because `+0xb4==0`) | S10 |
| 9 | S→C TS | On the first client TS frame, one write of `22 00 03` · `3e 00 09 00 00 00 02 7b 7d` · `04 00 0a 00 00 00 00 02 5b 5d` · `4a 00 07 00 00 00 00` | flags b0, b2, b3, b4 set at once; b1 set one main-thread frame later |
| 10 | C | S10: `0x7b0fe8` sees b0, b1, b3 and b4. It calls `0xc05870` (sets `+0xEC=1`), then `0xc071d0` (clears `+0x94`). Login state 8 (`0xbce054`) then moves to state 9. | done |
| 11 | S→C TS | `02 00 03` every 5 s for as long as the socket lives. The client answers 0x22 with `16 00 05 00 xx` and may send `0x69`; ignore both. If the client sends `0x96`, re-send `22 00 03`. | +0xEC kept |

### 1.2 Timing budget

| Budget | Value | Source | What it means for the server |
|---|---|---|---|
| Anubis attempt (whole chain: HTTP, controller, TS flags) | 60 000 ms from `0xc07020` | `online+0x250`, set in ctor `0xc17878` @`0xc17bd0`. Checked in the tail `0xc07b7c`. `+0xe8` is written only at `0xc070c4` and on timeout. | Loopback needs well under 5 s. Do **not** send `0x20`: it sets `+0x134`, which switches to 180 s and to the `atsv_`/`gltv_` paths. |
| HTTP re-issue | after 20 001 ms unanswered, up to 3 times | tail `0xc07ce0` | Answer at once. |
| Login state 8 retries | 4 pumps, each re-calling `0xc07020` | 02 §14.B | Each retry opens a fresh controller connection. |
| Login-wide budget | 120 000 ms since StartLogin | `online+0x254`, read by `0x8c0108` | Not reached on loopback. |
| Accept peek | 500 ms per connection | `server.cpp` | Spends 0.5 s of the 60 s budget once per controller connect. |
| TS idle watchdog (after the first TS frame) | **15 000 ms** (`+0x40`). 45 000 ms only when `online+0x2fc` is set. | `0xc0bcb8`. Checked: ctor `0xc057c4` `mov x9,#0x3a9800000000` then `stur x9,[x19,#0x3c]` sets `+0x40`=15000; `0xc0bcf4`→`0xbf7ec0` is `ldrb [x0,#0x2fc]` on `0x4e46a0()`. | Keepalive every 5 s. Never close the socket. |

---

## 2. Exact message formats

### 2.1 eve `GET config/{cid}/datacenters/{dc}/urls`

Keep the current keys (`status:"none"`, `pandora`, `federation`, `ecomm_api_root`, `crm_iap`) and add `game_portal`:

```json
{"crm_iap":"<base>crm_iap/","ecomm_api_root":"<base>ecomm_api_root/","federation":"<base>federation/",
 "game_portal":"<base>game_portal","pandora":"<base>pandora/","status":"none"}
```

- `game_portal` must be a JSON string and non-empty. `0xc86e18` returns -34 for a non-string, and `0xc07020` (`0xc070a0`-`0xc070b8`) returns 0 for an empty value.
- **`federation` must stay.** Its presence as a string is what selects mode 0 (`0xc07340`, `ca5428` → `+0x130==0`). Without it the client takes mode 1. Mode 1 needs a nonce→token Gaia exchange (`0xc8fab8`, callback `0xc39538`) whose endpoint is unknown.

### 2.2 Mode 0 HTTP: Federation sessions (request type 0x1902, service 0x15)

**Request** (`0xc06988` → `0xc8beb0`):
```
POST <federation url>/sessions/<urlenc client_id>/<urlenc credential>
Content-Type: application/x-www-form-urlencoded        (curl POSTFIELDS; parse the body even if the header is absent)
password=<urlenc cfg5+0x18>&device_id=<urlenc>          [&override_ip_geolocation=… never set]
```
- With our eve this arrives as `/federation//sessions/1924%3A56128%3A6.0.12a%3Aandroid%3Agoogleplay/<cred>`.
- After the router's `federation` prefix strip and empty-segment drop, it matches `sessions/{clientId}/{*credential}`.
- Use a tail match because the credential may decode to text containing `/`.
- There is no `access_token`.

**Response:** `200`, `application/json`, one top-level object. Read in state 4 at `0xc07904`:

| key | JSON type | Use |
|---|---|---|
| `encrypted_access_token` | string, non-empty | Stored at lobby `+0x2890`. It is echoed back as `access_token` in connect game. `0xc37fb8` refuses to send connect game if it is empty (status 3, err 0). |
| `room_id` | string | Room `+0x30`, then `CC+0x2928`, echoed in connect game. |
| `controller_host` | string, `"127.0.0.1"` | TCP target. |
| `controller_tcp_port` | **number** (`ctx.port`) | `asInt` `0x1053a30` returns 0 for a string. |

Example:
`{"controller_host":"127.0.0.1","controller_tcp_port":51780,"encrypted_access_token":"mc5o-anubis-1","room_id":"mc5offline-ts"}`

How the client reacts to other responses:
- `{}`, an empty array, or an unparsable body: `+0x20` stays empty → `awri` → login error **`glawri`**. This is what happens today: the misc fallback answers 200 `{}`.
- Any status other than 200/201/202/206 is treated as failure. The first failure flips mode to 1 permanently for the process.
- Code 606 parks the FSM in dead state 12.

### 2.3 Mode 1 HTTP: matchmaker quick_join_ah (fallback only; request type 0x1580, service 7)

**Request** (`0xc06c98` → `0xc82510`):
```
POST <matchmaker url>/rooms/<clientId>/automatch/quick_join_ah
access_token=<tok>&filter=ahgameserver&isolated=true&midgame_join=true&server_type=ts
```

**Response:** one room object, or an array whose first element is a room. Parsed by `0xc3c060`:

| key | JSON type | Use |
|---|---|---|
| `room_id` (or `id`) | string | Room id. |
| `controller_host` | string | TCP target. |
| `controller_port` | **number** | Note the name: `controller_port`, not `controller_tcp_port`. |
| `creator_datacenter` | string, optional | Must be a top-level key. Do not nest it under `custom_attributes`. |

Mode 1 never sets lobby `+0x2890` from this reply. Connect game in mode 1 therefore depends on the unknown nonce exchange.

### 2.4 Controller JSON (same TCP socket, plain, server speaks first)

**Framing:**
- One compact JSON object per message, terminated by `\n`, sent in **a single write**.
- Reader `0xc38d00`/`0xc40b58`: on the first `\n` in a recv batch it parses the whole batch, then resets the offset (`0xc39520`). Any bytes after the newline in the same batch are lost.
- So: one line per client request, nothing pipelined, and no binary appended.

**Success check** (`0xc36120`): `"success"` must be the boolean `true` or the string `"true"`. If it is missing, err=0. Keys `result` and `status` are never read.

| Dir | Exact line | Client handling |
|---|---|---|
| S→C, first, unsolicited | `{"action":"create connection","nonce":"mc5offline","success":true}` | Read in CC state 2. `nonce` must be a string (else reason 0xb). Wrong `action` → immediate disconnect. |
| C→S | `{"access_token":"<enc token>","action":"connect game","nonce_type":"targeted","room_id":"<room_id>","username":"anonymous:<anon id>"}` | Keys come out sorted (jsoncpp map). `nonce_type` is **absent in mode 1**. The nonce is not echoed. |
| S→C | `{"action":"connect game","slot":"0","success":true}` | Read in CC state 0xa. `slot` is optional; if present it must be a string. Then CC state 0xb (JSON reader stops), callback `0xc05bd0` type 0x14 → `+0x58=1`, S9. |
| (dead) C→S `login` | never sent | Rechecked: the only store of 7 to `0x1bc5834` is `0xc05dfc`, in the callback's type-0x12 failure retry (`cmp w0,#0x12` @`0xc05df0`). Nothing issues 0x12 first. |

Failure replies for reference: `code` = `room_full` gives err 5, `room_not_found` gives 6. Never send them.

### 2.5 TS binary (same socket, after CC state 0xb)

**Framing** (`0xbf7178`):
- `[type u8, 1..0xAD][len u16 BE, total frame length including the 3-byte header][payload]`.
- Payload integers are big-endian. The exception is the f32 in 0x45/0x46, which is little-endian.
- `str` = u16 BE length + bytes, no NUL. `blob32` = u32 BE length + bytes.
- Never send type 0, type > 0xAD, or len 0: they break the stream. Keep each poll well under 256 KB; a full buffer raises `AUTOMATCH_AH_TCP_TOO_SMALL`.

**When the server may start.** Wait for the client's first TS frame; it is always `0x01`.
- Every client TS send goes through `0xc0be30`, which drops the frame unless `+0x58` is set. So any binary frame from the client proves the TS reader is live and the lobby reader has stopped.
- Bytes sent earlier land in the lobby buffer (`lobby+0x34`, read while `+0x2920` is set) and never reach the TS splitter. This is required behaviour, not just caution.

**C→S frames the server will see:**

| Type | Bytes / layout | Server action |
|---|---|---|
| `0x01` ClientSendInitSettings (`0xc08008`) | u8 `0x33`; u8 `0x0b`; u32 hash(/hc.dat); str identity; str lang; str client_id; str portal (`game_portal` with https→http + `/%d/190/private/OfficialScripts/mc5Portal.wsgi`); str pandora URL; u8 `gate+0x5a`; str deviceID; str A; str B; str IGP; u8 `!0x4f90c0()`; u8 0; u32 days since epoch | Decode and log every field. Then send the burst below. |
| `0x49` | `49 00 03` | Reply `4a 00 07 00 00 00 00` (idempotent). |
| `0x16` | `16 00 05 00 xx` (reply to 0x22) | Log only. |
| `0x74` | `74 00 03` (profile ack) | Log only. |
| `0x69` | `69 00 04 bb` | Log only. |
| `0x21` | `21 00 04 bb` (profile-wait timeout) | Log, warn. |
| `0x96` | `96 00 03`. The UI handler `0xa47990` clears `+0xb0` (`0xa47bf4`/`0xa47d34`). | Reply `22 00 03`. |
| a line starting `{` | JSON (unexpected after 0xb) | Log it, reply `{"action":<same>,"success":true}\n`, expect EOF. |

**S→C burst.** Send once, in one write, on the first client TS frame. 29 bytes:

| Frame | Bytes | Effect, with evidence |
|---|---|---|
| 0x22 | `22 00 03` | `+0xb2`, `+0xb0` unconditionally (`0xc09da4`: `0x82a0d0`, `0xa47d40`). |
| 0x3e TCP_Config, plain | `3e 00 09 00 00 00 02 7b 7d` (blob32 `"{}"`) | `+0xb3` (`0xc0b1c0`). The content must never be exactly `"ERR"` (that gives `bhc`). 0x3e is the **plain** type; LZ4 goes on 0x3f. |
| 0x04 TCP_Tournaments, plain | `04 00 0a 00 00 00 00 02 5b 5d` (u8 flag 0, blob32 `"[]"`) | Queues event type 2 (`0xc0b790`/`0xc0b640`). The main-thread pump `0xc05e50` case 2 → `0xc06670` → `0xc05850` sets `+0xb1`, whatever the parse result. **This is the only source of b1.** |
| 0x4a | `4a 00 07 00 00 00 00` (u32 n=0) | `+0x83`, `+0xb4` (`0xc0adf8` → `0xc05860`). |

Optional, off by default for the first device test: a TCP_Profile.
- `0x03 [blob32 JSON]` or `0x27 [u32 clen][LZ4 block]`, compressed size ≤ 65 528 bytes.
- Not needed for the gate.
- The sub-loaders in `0x4f18a0` have not been verified against `default_profile()`, and they run on the main thread, so a bad profile could crash the game.

**Keepalive:**
- `02 00 03` every 5 s, starting right after the burst.
- Type 2 passes the splitter. In the handler, `0xc097f8`-`0xc09804` computes `sub w8,#3; cmp #0xa6; b.hi 0xc0b5a4`, so type 2 hits the default case, which only destroys the reader.
- The handler prologue stores `now` into `+0x3c` for every frame (`0xc097d0`), which refreshes the watchdog.
- Do not use 0x22 as the keepalive: it has side effects.

**Never send:** `0x3a`; `0x0d` or `0x3c` with non-null JSON; `0x33`; `0x20`; a 0x3e/0x3f whose payload is exactly `ERR`.

**Client frames after login** (02-post-auth-chain §17). Every one is fire-and-forget, so log it and send no reply:

| Frame | Sender | Meaning |
|---|---|---|
| `50 00 0b 00000002 0000 0000` | login FSM state 9 via `0xb840e0` | credential report; the optional ack `1f 00 03` has no effect |
| `0b <len> <str>` | online Update `0xc184f8`, one-shot | public info `{"display_name":..}` plus clan_* fields |
| `34 00 03` | `0xc184f8`; events timer `0x7b0da0` | tournaments refresh; the data arrives as 0x04/0x28 |
| `52 00 03` | OnResume `0x4f1f30` → `0xc1ad08` | app resumed |
| `ad <str> <str> <str>` | SetConsent `0x4f74e0` | consent mirror, "true"×3 or "false"×3 |
| `a8 00 03` | `0xc1c6c0`, result 0 | age-gate Restrictions OK (milestone) |
| `59 00 0b <u32 age> <u32>` | `0x8de9e8`, ok=1 | age gate passed (milestone) |

---

## 3. The `game_portal` value

```
"game_portal": ctx.base_url() + "game_portal"      // e.g. "https://127.0.0.1:51780/game_portal"
```
- No trailing slash, because the client appends `/%d/190/private/OfficialScripts/mc5Portal.wsgi`.
- The client never uses it as an HTTP base or as a TCP target. It only forwards it, with https changed to http, inside InitSettings (`0xc08084`-`0xc081d4`).
- The router already has `game_portal` as a strippable prefix.

---

## 4. Change list

### server/services/eve.cpp
1. In the urls handler, after the loop, add `o["game_portal"] = base + "game_portal";` (a string, no trailing slash). **Why:** `0xc07020` reads it straight from eve through `0xc86e18`; when it is missing, `+0x98` is empty, nothing starts, and login state 8 reports bare `gl` (02 §14.B).
2. Keep `"federation"` in `kEveServices`. **Why:** it selects mode 0 (`0xc0741c`, `ca5428`/`ca9e60`).
3. Fix the comments:
   - `game_portal` is read from eve, not located through pandora.
   - The "~1 KB buffer" theory was refuted (02 §14.B). Note that `game_portal` adds about 45 bytes (217 → about 262 bytes); see risk R9.

### server/services/matchmaker.cpp
1. **New Federation sessions handler** (mode 0, primary path):
   - Route `POST sessions/{clientId}/{*credential}`.
   - Form = `req.form`, or `parse_urlencoded(req.body)` when that is empty.
   - Return 200 with `{"controller_host":ctx.public_host,"controller_tcp_port":ctx.port (int),"encrypted_access_token":"mc5o-anubis-<n>","room_id":"mc5offline-ts"}`.
   - Optionally store the token and room in `ServerContext` (under a mutex) so meta.cpp can compare them.
   - Expose it as `Response federation_session(ServerContext&, const Request&)` in services.hpp.
   - **Why:** callback `0xc07d20` stores the body at `+0x20`; state 4 (`0xc07780`) needs those keys, otherwise `awri`.
2. **Mode 1 fix (defence in depth):**
   - Add `POST rooms/{clientId}/automatch/{automatcher}` **before** the `rooms/{clientId}/{*rest}` catch-all.
   - Response: `room_id` (string), `controller_host`, `controller_port` (int), `creator_datacenter` (= `ctx.data_center`). Keep `controller_tcp_port` and `encrypted_access_token`; they become harmless custom attributes.
   - Drop `host`, `port`, `status` and `result`.
   - **Why:** `0xc3c060` reads `controller_port` (`0xc3c5b4`); without it the port is 0.
3. Log the decoded form: `server_type`, `filter`, `isolated`, `midgame_join`, and `access_token` cut to 8 characters.
4. Rewrite the header comment. The real path is `rooms/{cid}/automatch/quick_join_ah`, and the body uses `filter=ahgameserver&server_type=ts`.

### server/services/misc.cpp (small, for robustness)
- In the fallback, if `method=="POST"` and the path contains `/sessions/` and the form has `device_id`, delegate to `federation_session()` and log `WARN federation via fallback`.
- **Why:** how the mode-0 base URL is resolved is only medium confidence (resolver `0xc77878` was not traced end to end). One wrong answer flips the process permanently to mode 1.

### server/services/meta.cpp (rewrite of `serve_meta_conn`)
1. **Greeting:** `{"action":"create connection","nonce":"mc5offline","success":true}\n`, one write. **Why:** without `success`, `0xc36120` gives code 2 → reason 0xd → `glhte_17_0`.
2. **Phase A loop** (`read_line`):
   - `connect game`: log `access_token`, `room_id`, `username` and `nonce_type`. Set mode = 0 if `nonce_type=="targeted"`, else 1, and warn loudly in mode 1: "process-sticky, restart app". Reply `{"action":"connect game","slot":"0","success":true}\n`. **Write nothing else**, then go to phase B.
   - `login`: reply `{"action":"login","success":true}\n` and warn "unexpected".
   - Any other verb: reply `{"action":<a>,"success":true}\n` and warn.
   - Remove `result` and `status` from all replies.
3. **Phase B:**
   - Delete the immediate `cfg`/`prof` push (current lines about 191-197). **Why:** it races the lobby reader (`0xc38f64`, `+0x2920`); the bytes are lost.
   - Read frames. If the first byte is `{`, handle it as a JSON line. On the **first TS frame** (expected `0x01`; warn if it is a different type), decode InitSettings and send the 29-byte burst from §2.5 in one write.
   - Handle `0x49` → `4a…` and `0x96` → `22 00 03`. Log `0x16`, `0x74`, `0x69` and `0x21`.
   - Optional profile behind a flag (e.g. env `MC5_TS_PROFILE=1`) as `0x27 [u32 clen][lz4]`. Drop the stray trailing `blob32("")`, and refuse to send if the frame would exceed 0xFFFF bytes.
4. **Keepalive thread:**
   - Started after the burst. Every 5 s it writes `02 00 03`.
   - Guard every write (reader replies and keepalive) with one `std::mutex`.
   - It stops on a flag plus condition variable when the read loop sees EOF. Join it before `c.close()`.
   - Never close the socket proactively. The client closes it on reset (`0xc377d0`).
   - Alternative without a second thread: add `set_read_timeout()` to `Conn` and treat EAGAIN as "send keepalive".
5. Leave `read_frame` as is: `len<3` means a broken stream, so log it and close.
6. Expect several sequential connections per login. Each retry or reset reconnects, so per-connection state must not leak between them.

### server/core/server.cpp
1. Move the 500 ms `MSG_PEEK` classification out of `accept_loop` into the per-connection thread. **Why:** the peek blocks all accepts for 0.5 s for every quiet socket. A controller reconnect can then delay concurrent HTTPS requests, such as the federation request on a retry.
2. Log the classification with the elapsed peek time and a per-connection id: `meta conn #N peer … quiet after 500ms`.
3. No protocol change is needed. The server-speaks-first detection matches the client: after `connect()` it sets `CC+0x2920=1` and sends nothing (`0xc393e0`).

### Docs to update afterwards
- `docs/protocol/tcp-messages.md`: plain/LZ4 pairs (0x03/0x27, 0x04/0x28, 0x07/0x29, 0x3e/0x3f, 0x45/0x46); multi-part first chunks 0xa7/0xa9 are exactly 65 000 bytes; 0x4a; 0x49; 0x96.
- `00-recon` §3.1-3.2 and `01-phase1b` §3: no `login` step; the `success` key; mode 0 Federation sessions.
- `02` §14: "event 2" is TCP_Tournaments, not a connection event.

---

## 5. Diagnostics

### Server side
- **meta.cpp:**
  - Connection id and ms elapsed since accept on every line.
  - Every JSON line in and out, verbatim, plus phase transitions (`A:greeted`, `A:connect-game`, `B:first-frame type=0x01 +Nms`, `B:burst-sent`).
  - Full decode of 0x01 (all 16 fields).
  - Every inbound frame as type, length and the first 48 bytes in hex.
  - Each outbound frame type.
  - The keepalive count, logged on the first and then every 12th.
  - On EOF: total lifetime and last phase.
- **Federation sessions handler:** client_id, credential, `device_id`, the length of `password`, the response body. Also a warning when it is reached via the fallback.
- **server.cpp:** the classification line described above.
- **misc fallback:** add an `ANUBIS?` tag when the path contains `sessions`, `automatch` or `nonce`. A nonce request would be the unknown mode-1 exchange.
- Optional: add the last meta phase, frame counters and the last 0x01 decode to `/_mc5/status`, so they can be read from the phone.

### Client side (`hosts/embedded/patch.cpp`, using the existing framework)
1. **Anubis suffix hook** at `0xc07fd8`.
   - It is the same shape as the existing login-error hook on `0xbcd618`: a 16-byte leaf `mov x1,x0; adrp; add x0,#0x840; b 0x40b838` that assigns a `const std::string&` to the global `0x1bc5840`.
   - Fingerprint `e1 03 00 aa e0 7d 00 d0 00 00 21 91 15 0e e0 17`.
   - Log `anubis-suffix: '<s>' lr=+0x…`. The lr identifies which of the 12 call sites fired. This gives the exact failure code before the `gl` popup appears.
2. **Poller thread** (50 ms; log only on change, with a timestamp).
   - `online = *(base+0x1bc62e8)`. Checked: the GOT slot `0x1b9b0d8` is RELATIVE to `0x1bc62e8`, and `0x4e46a0` → `0x511cb8` loads it.
   - `gate = *(online+0x1b8)` (`0x4ec770`). `CC = *(*(gate+0x50)+0x28)`. Check every pointer for null.
   - Globals: `0x1bc5834` (FSM state), `0x1bc5838` (pending op), byte `0x1bc583c`, `0x1bc585c` (retries), `0x1bc5860` (request generation), byte `0x1bc586c` (mode).
   - gateObj bytes: `+0x58, +0x59, +0x94 (int), +0xb0, +0xb1, +0xb2, +0xb3, +0xb4, +0xb5, +0xEC, +0x104, +0x105, +0x134`; and `now - +0x3c`, logged only when it exceeds 8 s (proves the keepalive works).
   - CC: `+0x2870` (CC state), byte `+0x2920`, `+0x29bc` (disconnect reason).
3. Optional: `install_trace_hook("AnubisFSM", 0xc071d8, …)`. The prologue `sub sp / str / stp` is relocatable, but the poller already covers it, and the function ticks about every 50 ms. Leave it off unless the poller misses transitions.

### Happy-path oracle
- **Server log, in order:** federation sessions (200), meta conn quiet, greet, connect game in (`nonce_type=targeted`), reply, first frame 0x01, burst, 0x49 → 0x4a, 0x16 in, keepalives.
- **Poller, in order:** state 2→3→1(op3)→4→5→1(op5)→8→1(op8)→9→10, flags b0/b3/b4 at once, b1 shortly after, EC=1, `+0x94`=0. Then login `fsm-state: 9`.

---

## 6. Risks and unknowns, ranked, with the login error each produces

Login error = `"gl"+suffix`. In `atg_` codes the four flag digits are in the order **b0 b3 b1 b4**. In `atgw_<!mode>_<op>_<ms>`, the first number is 1 in mode 0.

| # | Risk | Likelihood | Symptom |
|---|---|---|---|
| R1 | The mode-0 POST does not reach our handler, because the base resolution (`0xc77878`) differs. With misc's `{}` the login fails; with a non-2xx status the mode flips to 1 for good. | medium | `glawri` (got `{}`). After a flip: `glate_15_<err>` or `glatgw_0_6_<ms>` (stuck in the nonce exchange); retries keep failing until the app restarts. Mitigation: route + fallback sniff. |
| R2 | The controller JSON is rejected | low once fixed | `glhte_17_<err>` (create connection; 0 = `success` missing, 17 = success false, 21 = connect failed, 9 = peer closed). `glhte_20_<err>` (connect game; 0 can also mean it was never sent because the token was empty or Gaia had no anonymous credential, 29 = Gaia object missing). |
| R3 | The server never greets: the peek misclassified the socket, or it was routed to HTTP | low | `glatgw_1_5_<ms>` |
| R4 | The connect-game reply is never sent or never parsed | low | `glatgw_1_8_<ms>` |
| R5 | TS frames lost (sent too early) or never sent | eliminated by the 0x01 rule | `glatg_10_<ms>_D_0000` |
| R6 | One flag missing | low | `D_0111`: b0 (0x22 lost, or cleared by `0x96`). `D_1011`: b3 (0x3e). `D_1101`: b1 (0x04 lost, or the pump not running: pump needs `app+0x2c0==0`, `+0x218!=0`). `D_1110`: b4 (0x4a). |
| R7 | The watchdog fires after `+0xEC=1` because of silence > 15 s or a socket close | medium without keepalive | No `gl` code. The connection-lost popup (`0xb80d38`, visible through the existing `EnterConnLost` hook) or a reset (`+0xEC=0`). Fixed by the 5 s keepalive. The watchdog precondition `0x5e11b8(online)+0x3e0` is unknown, so keep the keepalive regardless. |
| R8 | The config consumer misbehaves on `"{}"` (`0x607180` → `0x5f52d0`, asynchronous, main loop) | low | A crash in the crash log, after the gate. Fallback: send an empty blob (`3e 00 07 00 00 00 00` → `0x60d638` reloads the cached /hc.dat). |
| R9 | Adding `game_portal` breaks eve/pandora parsing (the "1 KB" theory, already refuted) | low | Discovery fails before login (connection-error 0x1d). Fallback: shorten the value, e.g. `"<base>gp"`. |
| R10 | After a reset, the restart waits in S2 for the internal lobby event 0x17 | low | `glatg_2_<ms>_D_…` |
| R11 | HTTP code 606, or a failing state-3 issue | very low | `glatg_12_…` (dead state); `glaca` (device-id source `0x512660` failed, or a weak lock failed). |
| R12 | HTTP failures exhausted | low | `glafe_<code>` |
| R13 | A profile is enabled before it is validated | — | A main-thread crash inside the `0x4f18a0` sub-loaders. Keep the profile off for the first test. |
| R14 | Oversized data, or a kill message | none if the rules are followed | `glAUTOMATCH_AH_TCP_TOO_SMALL`, `glbanned`, `glahwv`, `glavf`, `glbhc` |
| R15 | `game_portal` missing or empty, or the thread failed to start | today's state | bare `gl` within about 1 s |
| — | Open questions | | The username suffix (any string is fine). The endpoint behind the mode-1 nonce exchange (`0xc8fab8`: param keys `0x1b9c4e0` accountType, `0x1b9cdb8`, `0x1b9c680`). What uses the 0x4a blob and the slot later. Which in-game features read `+0xEC` (the getter `0x707ec0` is ICF-shared). |

---

## 7. Where the investigators disagreed, and how it was settled

| Disagreement | Outcome | Basis |
|---|---|---|
| Does the client send `login`? (ts_msgs said yes; anubis_tcp said no) | **No** | Own scan of every store to `0x1bc5834`: 7 is written only at `0xc05dfc`, the type-0x12 failure retry. |
| Watchdog limit 45 s (ts_msgs) vs 15 s (events) | **15 s**, read from `online+0x2fc`, not `app` | Own disasm of `0xc0bcb8` and ctor `0xc057c4`/`0xc057d8`. |
| Pump precondition `app+0x2c1` (events verifier left it open) | **Not a risk** | `0x833050` calls `0x833808` at `0x8333f4`, which clears `+0x2c1` through `0x833db0` at `0x833920`, immediately before StartLogin `bl 0xbcd410` at `0x833400`. The device log shows `StartLogin … lr=+0x833404`. |
| "Wait for 0x01" required or just prudent | **Required** | The lobby reader shares the fd while `+0x2920` is set (events verifier). Also, any client TS frame implies `+0x58` (`0xc0be30`). |
| Keepalive frame type | **`02 00 03`** | Own check: unsigned `b.hi` at `0xc09804`, and the default case `0xc0b5a4` is benign. |
| Mode: quick_join_ah (TS/events areas) vs Federation (fsm_http) | **Mode 0, Federation** | Because eve serves `federation`. Not re-traced by me; the fsm_http verifier confirmed `ca5428`. |
| Minimum 0x3e: `"{}"` vs empty | Both set b3. **Use `"{}"`** | Empty is the fallback (R8). |
| What a bad frame does | Verifier is right: the rest of the recv chunk is dropped | Irrelevant to us, because we never send one. |