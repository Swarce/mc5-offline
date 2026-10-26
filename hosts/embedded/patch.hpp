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

} // namespace mc5
