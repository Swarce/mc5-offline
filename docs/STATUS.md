# Status

Device-test history and the current state. Newest first.

## November 2026: M0 first on-device run (Galaxy S22) + TLS transport

* **The patched game runs on hardware.** The full re-signed split set (base + arm64 + xxhdpi +
  all asset packs) installed and booted. logcat confirms the whole M0 chain fires on-device:
  `libmc5offline.so` loads at +0 ms (before `libMC5.so` at +89 ms), the server listens on
  127.0.0.1:51780, all **3 libMC5 http patches apply at runtime** (fingerprints matched), GOT
  hooks install, and the crash handler/watchdog run. The game reached the campaign and tried the
  tutorial.
* **Gap found and fixed:** no Federation request reached the server — the only redirected traffic
  was `sink.gameloft.com` telemetry over **:443**, i.e. the client speaks **HTTPS**, which our
  plain-HTTP M0 server couldn't answer (so the tutorial failed with "can't connect"). Added a
  **loopback TLS listener** (mbedTLS 3.6.2, self-signed cert, verify-none) that auto-detects a TLS
  ClientHello vs plain HTTP on the same port and terminates TLS over the fd ([patches.md](patches.md),
  `hosts/embedded/tls.cpp`). Host-verified with curl: HTTPS and HTTP both serve eve/auth 200s.
  The eve http patch + scheme-rewrite neutralisation stay (http still works; https now also does).
* Diagnostics extended: the listener logs a TLS ClientHello, and the redirect logs every libMC5
  connect (host:port). Shipped as an inherited base+config update (keeps the installed asset packs).
* **Second on-device run:** the connect log showed the game reaching **public AWS IPs on :443**
  directly — libcurl resolves via c-ares, bypassing the `getaddrinfo` hook — and the loopback TLS
  handshake **reset** (`-0x0050`, `NET_CONN_RESET`). Two follow-ups: (1) the `connect` hook now
  redirects **any** :443/:80 (public IP or loopback) to our server, resolver-proof; (2) TLS pinned
  to 1.2 with full mbedTLS handshake logging to pin down the reset.
* **Third on-device run:** the trace was decisive — our server completes the whole handshake,
  then the client sends a fatal **`unknown_ca`** alert (48). The Gaia client is **Boost.Asio +
  OpenSSL** and it **verifies** the server cert (recon was wrong that TLS verification is off).
  Fix: patch the exported asio verify callback (`…engine::verify_callback_function`) to accept
  any cert — in-memory, fingerprint-checked, resolved by symbol ([patches.md](patches.md) #4);
  mbedTLS logging dropped to level 1. Awaiting the next log: TLS should now complete and
  eve/pandora/auth should reach the server (`GET … -> 200`).

## October 2026: M0.5 diagnostics (host-verified, no device yet)

* `hosts/embedded/diag.{hpp,cpp}` — [diagnostics.md](diagnostics.md). Boot trace
  (`[boot +Nms]` milestones from load to hooks), native crash reporter (SEGV/ABRT/BUS/ILL/FPE
  on a sigaltstack, async-signal-safe `module+offset` backtrace resolved from `/proc/self/maps`,
  then chains to the platform handler), watchdog (heartbeat + periodic thread-state dump), and a
  phone-readable `mc5offline.log` copy (external files dir preferred, `adb pull`-able). Installed
  at `JNI_OnLoad`, before the server, so startup crashes are still caught.
* Host-tested under ctest (`tests/test_diag.cpp`): a child faults, and the handler emits the
  crash line and a resolved backtrace (`libMC5.so +0xNNNNNN` → Ghidra addr = offset + 0x100000).
  Both ABIs build clean. M0 is now code-complete and awaiting the device test.

## October 2026: M0.4 patcher (host-verified, no device yet)

* `patcher/` (Java/Gradle, dexlib2) turns the player's own split set into a re-signed,
  offline-ready set — [patcher.md](patcher.md). One structural dex edit makes
  `FrameworkApplication.attachBaseContext` load `libmc5offline.so` first (via an injected
  `MC5Offline.boot()`); `libmc5offline.so` is added to each ABI split uncompressed +
  page-aligned (the app is `extractNativeLibs=false`); every APK (base, ABI/density splits,
  asset packs) is re-signed with one player key and `apksigner verify`ed, so
  `install-multiple` accepts the set. Base identity is fingerprinted first; `--dry-run` and
  `--force` provided.
* Verified on the real 601213 base + arm64 split + xxhdpi + an asset pack: injected
  bytecode disassembles correctly (boot() = `loadLibrary("mc5offline")`, called as
  instruction 0 of attachBaseContext); `.so` present, STORED, page-aligned; one shared
  signer cert across all outputs; whole-archive alignment check passes. Not yet installed on
  a device — that is the end-of-M0 test (needs M0.5 diagnostics first).

## October 2026: M0.2/M0.3 embedded library + redirect (no device yet)

* `libmc5offline.so` cross-compiles for arm64-v8a and armeabi-v7a (NDK r26d, c++_static);
  JNI_OnLoad/`mc5offline_start`/injected-`init`; self-starts the server on load.
* GOT/PLT hook engine redirects libMC5's `getaddrinfo`/`connect` to loopback (unit-tested
  on the host with a victim library). Transport decision (owner): plain HTTP on loopback via
  two fingerprint-verified in-memory patches to the loaded libMC5 (eve URL + scheme rewrite,
  arm64), leaving the on-disk .so byte-identical — no TLS stack ([patches.md](patches.md)).
* Both ABIs build; host unit tests pass. Not yet device-tested (needs the patcher, M0.4).

## October 2026: M0.1 server core (desktop, no device yet)

* The Federation server builds and runs on the desktop (`server/`, one C++17 tree, no
  third-party deps). The boot discovery + auth chain answers: eve datacenters/urls,
  pandora locate, auth authorize/users/me/verify/encrypt_token, plus a catch-all that
  logs every unknown request and answers `200 {}`. Account ids are `sha1(credential)[:24]`;
  tokens are self-describing. Unit tests (JSON, router) pass; the chain is verified with curl.
* Build/run: [DEV-LOOP.md](DEV-LOOP.md).
* Next in M0: cross-compile the same tree to `libmc5offline.so` (NDK), native GOT hooks +
  loopback TLS, the patcher, and diagnostics.

## October 2026: Phase 1b (analysis only)

* [research/01-phase1b.md](research/01-phase1b.md): no local-profile mode; the profile is a JSON document pushed by
  the transaction server (TS) over the TCP meta channel; the TS is joined through the matchmaker (`ts` room) and the
  Anubis controller and is not in the client; match rules and bots run in the client under an authority role.
* Generated catalogs: [protocol/tcp-messages.md](protocol/tcp-messages.md),
  [protocol/federation-requests.md](protocol/federation-requests.md); tools in [../tools/](../tools/).
* Waiting for: a private copy of the asset-pack backup (for the economy tables), then M0.

## October 2026: Phase 1 recon (no build yet)

* Inputs: the 6.0.12a split set (base, arm64-v8a, xxhdpi). Missing: the five asset packs, the 32-bit split and the
  `Android/data`/`Android/obb` folders ([BACKUP.md](BACKUP.md)).
* Findings and the proposal: [research/00-recon.md](research/00-recon.md).
* Decisions (owner, October 2026): the recommended architecture is approved (MCVS code may be reused where it
  fits); Phase 1b comes before M0; the live DLC mirror is on hold (the owner has full backups of the downloaded
  data); the public `Test` release that carried the APK is to be deleted by the owner (this session cannot delete
  releases).

No device tests yet.
