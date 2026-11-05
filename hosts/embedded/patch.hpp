// In-memory patches to the loaded copy of libMC5 (never the file on disk, so any
// integrity hash of the .so still matches). Each patch verifies the exact shipped
// bytes first (a fingerprint) and refuses on mismatch, so it only ever touches the
// one build it was derived from (6.0.12a, arm64-v8a, build-id 475ac80e…).
//
// Purpose (chosen for M0, 00-recon.md 6.2): make the Gaia path plain HTTP on
// loopback so no TLS stack is needed — repoint the hard-coded eve URL at our
// server and neutralise the http->https scheme rewrite. arm64 only; the 32-bit
// libMC5 is a different binary whose offsets are not yet mapped.
//
// C++17.
#pragma once

namespace mc5 {

// Applies the http-redirect patches to the loaded libMC5 for the given server
// port. Returns the number of patch sites successfully applied. Logs each site
// (applied / fingerprint-mismatch / unsupported ABI).
int apply_libmc5_http_patches(int http_port);

// Neutralises the game's TLS server-certificate verification so our self-signed
// loopback cert is accepted (the client otherwise rejects it with a fatal
// unknown_ca alert). Patches the exported asio::ssl verify callback to return
// "accept", resolved by symbol at runtime (robust across builds). Returns 1 if
// applied. arm64 only. See docs/patches.md.
int apply_libmc5_tls_bypass();

// Forces the Gaia login "connected" gate (FUN @ 0x707ec0, `return *(u8*)(this+0xEC)`)
// to always return true, so the login FSM reaches its success terminal and fires
// onLoginCompleted instead of diverting to the stuck state that triggers
// popupConnectionLost + the ~1/s re-login loop. Overwrites only the first instruction
// (ldrb -> mov w0,#1); 8-byte fingerprint-guarded. Returns 1 if applied. arm64 only.
// See docs/research/02 §10.
int apply_libmc5_connected_gate();

// Diagnostic: replaces the Gaia "[IRISCfgProvider]" logger (a no-op in the shipped
// release build, since its sink is null) with a trampoline that tees each discovery
// message to logcat, so the game reports its own boot/discovery trace ("Getting
// URLs from Eve", "Discovered Pandora URL: …", "Failed to parse Pandora URL from
// Eve response", …). Fingerprint-guarded; returns 1 if installed. arm64 only.
int install_iris_log_hook();

// Diagnostic: installs entry-trace hooks on the Gaia online-login Lua bridge
// (onLoginCompleted, onLoginFailed[code in w2], onDisconnected) plus StartLogin, to
// capture exactly what the game decides after the HTTP login chain and what re-triggers
// the ~15s re-login loop. Each is a continuation trampoline that logs (label, x0, x1,
// x2, caller-LR as a libMC5 file offset) then runs the original intact. The first 4
// instructions of every target are verified position-independent before relocation;
// refuses otherwise. Returns the number installed. arm64 only. See docs/research/02 §7.
int install_login_trace_hooks();

// Diagnostic: replaces the 16-byte Gaia SetLoginError leaf (0xbcd618) with a jump to a
// logger that writes the login error code ("glrer_…", "glgc_%d", "gldahd", …) and its
// caller to logcat, then performs the original std::string assignment. Any non-empty
// code is what makes the game show "Failed to connect!" / "Servers are temporarily
// overloaded". Behaviour unchanged; 16-byte fingerprint-guarded; returns 1 if installed.
// arm64 only. See docs/research/02 §13.
int install_login_error_hook();

// Diagnostic for the game_portal/Anubis connect (login state 8): (1) replaces the
// 16-byte Anubis error-suffix setter leaf 0xc07fd8 with a logger (the suffix becomes
// the login error "gl<suffix>"; caller LR names which of its call sites fired), and
// (2) starts a read-only poller thread that logs, on change, the Anubis FSM globals,
// the gate object's flag bytes (+0xb0..+0xb4 -> +0xEC) and the controller connection
// state. All poller reads use process_vm_readv (no crash on a stale pointer).
// Behaviour unchanged; fingerprint-guarded. Returns the number of parts started.
// arm64 only. See docs/research/02 §15.
int install_anubis_diag();

// Diagnostic for the first-run age/gender gate (the pre-tutorial "connection error"
// was its "ageLimit" popup): entry-trace hooks on the age submit, RequestRestrictions,
// the Restrictions callback/completion, the age callback and the native notification
// popups (names every popup by tag). Logging only, each site fingerprint-verified.
// Returns the number of hooks installed. arm64 only. See docs/research/02 §17.
int install_age_gate_diag();

// Fingerprint-guarded rewrite of the level-up rewards accessor 0x628af8 so an
// unsized table yields an empty range instead of NULL (the Profile->stats crash at
// 0x95e6ec). Returns 1 if applied.
int apply_levelup_rewards_guard();

} // namespace mc5
