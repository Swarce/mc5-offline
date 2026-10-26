// Installs the libMC5 network redirect: getaddrinfo for *gameloft* hosts resolves
// to loopback, and connect to loopback :80/:443 is repointed at our HTTP/TLS ports.
// Together with gothook this sends the game's Gaia traffic to our in-process server
// without changing any byte of libMC5.
//
// C++17.
#pragma once

namespace mc5 {

// Starts a background thread that waits for libMC5.so to be loaded (our library is
// loaded first, before the game loads libMC5), then installs the GOT hooks. Safe to
// call once; the thread exits after installing or after a timeout.
void start_redirect_installer(int http_port, int tls_port);

} // namespace mc5
