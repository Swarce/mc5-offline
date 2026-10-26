# Status

Device-test history and the current state. Newest first.

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
