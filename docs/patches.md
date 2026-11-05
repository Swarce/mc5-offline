# libMC5 patches

Every patch here is applied **in memory, to the loaded copy only** — the `libMC5.so`
file on disk is never modified, so any integrity hash the game computes of its own
library still matches the shipped bytes. Each patch verifies the exact original bytes
(a fingerprint) before writing and refuses on any mismatch, so it only ever applies to
the one build it was derived from.

Target: `libMC5.so`, MC5 6.0.12a (versionCode 601213), `arm64-v8a`, build-id
`475ac80eb88f7bffac8cb3b0a532c66852b94654`. Offsets are ELF virtual addresses; the
runtime address is the library's load bias + the vaddr. These are arm64 only; the
32-bit `libMC5.so` is a different binary whose offsets are not yet mapped (the S22
device test runs arm64).

Applied by `apply_libmc5_http_patches()` (`hosts/embedded/patch.cpp`) once libMC5 is
loaded, before Gaia initialises.

## Why these patches exist (M0 transport)

The client's first backend call is HTTPS to `eve.gameloft.com`. It does not verify
certificates, but it still performs a TLS handshake, so a plain-HTTP server cannot
answer it unchanged. Rather than add a TLS stack to the embedded library, M0 first
tried making the Gaia path plain HTTP on loopback (the same thing MCVS did by pointing
eve at an `http://` URL). That needs exactly two things patched in libMC5; everything
else is served by our own URLs. This is the allowed "patch only hostnames/TLS, and say
why" case from the project rules.

**On-device result (Nov 2026):** the first Galaxy S22 run showed the client still speaks
**HTTPS** — the only traffic reaching our redirect was `sink.gameloft.com` telemetry over
port 443, and no plain-HTTP request ever arrived, so the tutorial failed with "can't
connect". The plain-HTTP assumption did not hold, so a **loopback TLS listener was added**
(`hosts/embedded/tls.cpp`, mbedTLS 3.6.2, self-signed cert, `VERIFY_NONE` — the client does
not check certificates). The server auto-detects a TLS ClientHello (first byte `0x16`) vs
plain HTTP on the same port 51780 and terminates TLS over the socket. The two patches below
stay and are complementary: the eve literal points the first call at our server and the
scheme-rewrite neutralisation keeps our returned URLs intact; whether the client then uses
http or https, the one listener serves both.

## Patch sites

| # | Site | ELF vaddr | Fingerprint (original) | Change | Why |
|---|---|---|---|---|---|
| 1 | eve URL literal | `0x14ad840` | `https://eve.gameloft.com\0` (25 B) | → `http://127.0.0.1:<port>\0`, null-padded | Point the hard-coded environment switcher at our loopback server over http |
| 2 | scheme rewrite (pandora) | `0xc85db0` | `ff 03 02 d1 f5 2b 00 f9 f4 4f 06 a9 fd 7b 07 a9` (prologue) | first instruction → `ret` (`c0 03 5f d6`) | The client upgrades the located pandora URL http→https; neutralised so our http URL is used as-is |
| 3 | scheme rewrite (federation) | `0xc86020` | same prologue | first instruction → `ret` | Same, for the `federation` URL |
| 4 | asio TLS verify callback | `0x1252c70` (sym `_ZN4asio3ssl6detail6engine24verify_callback_functionEiP17x509_store_ctx_st`) | `f5 0f 1d f8 f4 4f 01 a9` (prologue) | → `mov w0,#1 ; ret` (`20 00 80 52 c0 03 5f d6`) | Accept our self-signed loopback cert; the client otherwise rejects it with a fatal `unknown_ca` alert |
| 5 | level-up rewards accessor | `0x628af8` (68 B, the whole function) | `3f000071 cd010054 080043f9 … 00fc42f9 c0035fd6` | first two words → `ldr x9,[x0,#0x5f8] ; cbz x9,0x628b34`; word 15 → `add x0,x0,#0x5f8` | An unsized level-up table returns an empty range instead of NULL: the Profile → stats crash at `0x95e6ec` |

Patches 2 and 3 are single-caller leaf helpers (called only from the scheme-upgrade
parent at `0xc85c40`); returning immediately leaves the URL string unchanged and does
nothing else.

Patch 4 (`apply_libmc5_tls_bypass`) is the on-device fix for the login-screen failure
(Nov 2026): the game's Gaia client is **Boost.Asio + OpenSSL** and it **does** verify
the server certificate — the first device run with a real TLS listener got a fatal
`unknown_ca` alert mid-handshake. `asio::ssl::detail::engine::verify_callback_function`
is the callback OpenSSL invokes per certificate; it is exported (WEAK), so it is resolved
by symbol at runtime (vaddr `0x1252c70` is only a fallback) and its prologue replaced with
`return 1`, so every server cert is accepted. This is the allowed "patch only TLS, and say
why" case — it changes only certificate trust on loopback, nothing else.

Patch 5 (`apply_levelup_rewards_guard`, applied with the diagnostics once libMC5 is loaded) is
the backstop for the Profile → stats crash (research/04-progression.md §1.1). The accessor
`0x628af8(cfg, level)` returns `&cfg->rewards[level]`, a vector of vectors at `cfg+0x5f8` that
only the config parser sizes (`0x614c78`, from `game["_level_up_rewards"]`). While the server
sent the empty config `{}`, the table was never allocated, the accessor returned `begin = NULL`,
and its three callers (`0x95cb20` stats page, `0x941738` / `0xa3e820` level-up popups) crashed on
`ldp x8,x9,[x0]`. The primary fix is server-side (TCP_Config now carries `"game"`). The patch
makes an empty table return `&cfg->table` itself (`{NULL,NULL}`), so the callers' own
`begin == end` check skips the loop. A non-empty table behaves exactly as before. The whole
68-byte function is fingerprint-checked before writing. The disassembly of the patched bytes
was verified with capstone.

## Not patched

The integrity/signature paths (`ysM`, `GetSignature`) are **not** patched: they report
to the game server, which is us, and we simply never ask for or enforce them
(`01-phase1b.md` §5, `00-recon.md` §1.1). The GOT `getaddrinfo`/`connect` hooks
(`redirect.cpp`) are not patches to libMC5's code — they repoint its import table in
memory and are a backstop for hosts not reached through our returned URLs.
