// Verifies the GOT hook actually redirects an imported-symbol call in a loaded
// shared object, and leaves other objects alone. The arm specifics can't run on
// the host, but the ElfW()-based mechanism is the same; this guards the logic.
#include <dlfcn.h>
#include <cstring>
#include <string>

#include "../hosts/embedded/gothook.hpp"
#include "check.hpp"

static const char* g_fake = nullptr;
extern "C" char* fake_getenv(const char* /*k*/) { return const_cast<char*>(g_fake); }

int main() {
    void* h = dlopen(VICTIM_PATH, RTLD_NOW | RTLD_GLOBAL);
    CHECK(h != nullptr);
    if (!h) return 1;

    using Fn = const char* (*)(const char*);
    Fn victim = reinterpret_cast<Fn>(dlsym(h, "victim_lookup"));
    CHECK(victim != nullptr);
    if (!victim) return 1;

    // Before hooking, a made-up variable resolves to null via the real getenv.
    CHECK(victim("MC5_NO_SUCH_VAR_XYZ") == nullptr);

    // Presence check.
    CHECK(mc5::so_loaded("victim"));
    CHECK(!mc5::so_loaded("definitely_not_loaded_zzz"));

    // Hook getenv only within the victim object.
    g_fake = "hooked!";
    void* orig = nullptr;
    int n = mc5::got_hook("victim", "getenv", reinterpret_cast<void*>(fake_getenv), &orig);
    CHECK(n >= 1);
    CHECK(orig != nullptr);

    // Now the victim's getenv is redirected; the process's own is not.
    const char* r = victim("MC5_NO_SUCH_VAR_XYZ");
    CHECK(r != nullptr && std::string(r) == "hooked!");
    CHECK(::getenv("MC5_NO_SUCH_VAR_XYZ") == nullptr); // our process unaffected

    // Hooking a missing symbol/library patches nothing.
    CHECK(mc5::got_hook("victim", "no_such_symbol_qqq", reinterpret_cast<void*>(fake_getenv), nullptr) == 0);
    CHECK(mc5::got_hook("no_such_lib_qqq", "getenv", reinterpret_cast<void*>(fake_getenv), nullptr) == 0);

    if (mc5test::failures() == 0) std::printf("test_gothook: OK\n");
    return mc5test::failures();
}
