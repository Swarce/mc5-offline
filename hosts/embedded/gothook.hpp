// GOT/PLT hooking: redirect an imported symbol in an already-loaded shared library
// to our own function, by overwriting its GOT slot. This changes no bytes of the
// target .so on disk and nothing in its .text; only the writable GOT (relocation)
// slot in memory is repointed. Used to send libMC5's getaddrinfo/connect to our
// loopback server (00-recon.md 6.2 option A: no game-code patch).
//
// Bitness-agnostic via ElfW(). Works on Android (bionic) and desktop Linux (glibc),
// so the mechanism can be unit-tested on the host before the device.
//
// C++17.
#pragma once

#include <cstddef>

namespace mc5 {

// True if a shared object whose soname/path contains `so_substr` is currently
// loaded in the process.
bool so_loaded(const char* so_substr);

// Overwrite the GOT slot for imported `symbol` in every loaded shared object whose
// path contains `so_substr`, repointing it at `replacement`. If `out_original` is
// non-null it receives the previous target the first time the symbol is found.
// Returns the number of slots patched (0 if the library or symbol was not found).
int got_hook(const char* so_substr, const char* symbol, void* replacement, void** out_original);

} // namespace mc5
