// Installs the libMC5 network redirect: getaddrinfo for *gameloft* hosts resolves
// to loopback, and connect to loopback :80/:443 is repointed at our HTTP/TLS ports.
// Together with gothook this sends the game's Gaia traffic to our in-process server
// without changing any byte of libMC5.
//
// C++17.
#pragma once

#include "patch.hpp" // ItemSink

namespace mc5 {

// Starts a background thread that waits for libMC5.so to be loaded (our library is
// loaded first, before the game loads libMC5), then installs the GOT hooks. Safe to
// call once; the thread exits after installing or after a timeout.
// item_sink (may be null) receives the unlock-code item lists read from the game's
// own memory (install_item_dump_hooks).
void start_redirect_installer(int http_port, int tls_port, ItemSink item_sink = nullptr);

} // namespace mc5
