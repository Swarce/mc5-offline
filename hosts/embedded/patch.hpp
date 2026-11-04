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

// Diagnostic: replaces the Gaia "[IRISCfgProvider]" logger (a no-op in the shipped
// release build, since its sink is null) with a trampoline that tees each discovery
// message to logcat, so the game reports its own boot/discovery trace ("Getting
// URLs from Eve", "Discovered Pandora URL: …", "Failed to parse Pandora URL from
// Eve response", …). Fingerprint-guarded; returns 1 if installed. arm64 only.
int install_iris_log_hook();

// Diagnostic: installs entry-trace hooks on the Restrictions/legislation functions that
// decide the post-login flow (ProcessCompliancy, Restrictions::Init, GetLegislationVersion,
// RequestRestrictions, the compliancy-fetch vtable slot, the restricted-mode signal and
// the boot legislation loader). Each is a continuation trampoline that logs the call
// (label, x0/x1, caller-LR as a libMC5 file offset; Restrictions-object hooks also dump
// the +0x100/+0x178/+0x218 gate fields) and then runs the original intact. The first 4
// instructions of every target are verified position-independent before relocation;
// refuses otherwise. Returns the number installed. arm64 only. See docs/research/02 §7.
int install_legislation_trace_hooks();

} // namespace mc5
