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
answer it unchanged. Rather than add a TLS stack to the embedded library, M0 makes the
Gaia path plain HTTP on loopback (the same thing MCVS did by pointing eve at an
`http://` URL). That needs exactly two things patched in libMC5; everything else is
served by our own URLs. This is the allowed "patch only hostnames/TLS, and say why"
case from the project rules. Loopback TLS with zero patches remains a possible
alternative (see `docs/ARCHITECTURE.md`).

## Patch sites

| # | Site | ELF vaddr | Fingerprint (original) | Change | Why |
|---|---|---|---|---|---|
| 1 | eve URL literal | `0x14ad840` | `https://eve.gameloft.com\0` (25 B) | → `http://127.0.0.1:<port>\0`, null-padded | Point the hard-coded environment switcher at our loopback server over http |
| 2 | scheme rewrite (pandora) | `0xc85db0` | `ff 03 02 d1 f5 2b 00 f9 f4 4f 06 a9 fd 7b 07 a9` (prologue) | first instruction → `ret` (`c0 03 5f d6`) | The client upgrades the located pandora URL http→https; neutralised so our http URL is used as-is |
| 3 | scheme rewrite (federation) | `0xc86020` | same prologue | first instruction → `ret` | Same, for the `federation` URL |

Patches 2 and 3 are single-caller leaf helpers (called only from the scheme-upgrade
parent at `0xc85c40`); returning immediately leaves the URL string unchanged and does
nothing else.

## Not patched

The integrity/signature paths (`ysM`, `GetSignature`) are **not** patched: they report
to the game server, which is us, and we simply never ask for or enforce them
(`01-phase1b.md` §5, `00-recon.md` §1.1). The GOT `getaddrinfo`/`connect` hooks
(`redirect.cpp`) are not patches to libMC5's code — they repoint its import table in
memory and are a backstop for hosts not reached through our returned URLs.
