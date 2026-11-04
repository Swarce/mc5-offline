// Loopback TLS termination for the embedded server (M0 transport fix).
//
// On-device the game speaks HTTPS to its backend hosts (and to our loopback
// redirect), so a plain-HTTP server never completes the handshake. This wraps an
// accepted fd in a server-side TLS session (mbedTLS, embedded self-signed cert)
// so those requests decrypt and reach the same Router. The client does not verify
// certificates, so the self-signed cert is accepted.
//
// Only the embedded (Android) build links mbedTLS; the desktop build never calls
// this, keeping the core TLS-free.
//
// C++17.
#pragma once

#include <memory>

#include "../../server/core/server.hpp"

namespace mc5 {

// Terminate TLS over an accepted socket fd (performs the server handshake).
// Returns a Conn speaking the HTTP state machine over TLS, or null on failure.
std::unique_ptr<Conn> tls_upgrade(int fd);

} // namespace mc5
