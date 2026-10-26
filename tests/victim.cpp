// A victim shared library for the GOT-hook test. It imports getenv through its PLT
// (like libMC5 imports connect/getaddrinfo), so hooking "getenv" in this object
// redirects the call without touching the victim's code.
#include <cstdlib>

extern "C" const char* victim_lookup(const char* key) {
    return getenv(key);
}
