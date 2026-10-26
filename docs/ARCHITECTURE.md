# Architecture (approved direction, October 2026)

The full proposal with the evidence behind it is in [research/00-recon.md](research/00-recon.md) §6. Summary:

* **What is dead after the shutdown:** Gameloft's Federation HTTP backend (eve, pandora, auth, storage, CRM, social,
  messaging, alerts, leaderboards, assets/Iris, matchmaker, ecomm), the Anubis lobby/controller, the transaction
  server (TS) that holds the player profile, and the match servers (`ahgameserver`).
* **What the client already has:** the match rules and bots, run by whichever peer holds the authority role
  ([research/01-phase1b.md](research/01-phase1b.md) §5). The TS is not in the client and is reimplemented from the
  client's parsers and builders; the GS becomes a relay plus room/match lifecycle.
* **One native library, `libmc5offline.so`,** loaded by the game process before `libMC5.so`. It runs the Federation
  HTTPS server, the Anubis lobby/controller, the TS (meta channel), the GS relay, on-device storage and the
  diagnostics. The game is redirected by GOT hooks of libMC5's libc imports (`getaddrinfo`, `connect`), so no
  byte of `libMC5.so` changes; the server answers with TLS on loopback.
* **Patcher** (player's own splits in, one APK out): merges the splits, keeps every supplied ABI, makes
  `MainActivity` load our library, points the asset-pack paths at a local copy, re-signs with the player's key.
  Every patch checks the exact shipped bytes first and has a dry run.
* **The same server source** builds for the desktop (development loop, later PC/VPS hosting for internet play).
