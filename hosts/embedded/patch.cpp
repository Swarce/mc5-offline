#include "patch.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#include "../../server/core/log.hpp"
#include "gothook.hpp"

namespace mc5 {

#if defined(__aarch64__)

namespace {

// ELF vaddrs in libMC5.so 6.0.12a (arm64-v8a, build-id 475ac80e…), from our own
// analysis of the player's library. Each is guarded by a byte fingerprint below.
constexpr uintptr_t kEveLiteralVaddr = 0x14ad840; // "https://eve.gameloft.com\0" (25 bytes incl null)
constexpr uintptr_t kRewritePandoraVaddr = 0xc85db0; // http->https scheme upgrade (pandora)
constexpr uintptr_t kRewriteFederationVaddr = 0xc86020; // http->https scheme upgrade (federation)

const char kEveOriginal[] = "https://eve.gameloft.com";       // 24 chars
const unsigned char kFnPrologue[16] = {0xff, 0x03, 0x02, 0xd1, 0xf5, 0x2b, 0x00, 0xf9,
                                       0xf4, 0x4f, 0x06, 0xa9, 0xfd, 0x7b, 0x07, 0xa9};
const unsigned char kAarch64Ret[4] = {0xc0, 0x03, 0x5f, 0xd6};

bool set_prot(void* addr, std::size_t len, int prot) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t start = reinterpret_cast<uintptr_t>(addr) & ~(static_cast<uintptr_t>(ps) - 1);
    uintptr_t end = (reinterpret_cast<uintptr_t>(addr) + len + ps - 1) & ~(static_cast<uintptr_t>(ps) - 1);
    return mprotect(reinterpret_cast<void*>(start), end - start, prot) == 0;
}

std::string hexpre(const unsigned char* p, int n) {
    std::string s;
    char b[4];
    for (int i = 0; i < n; ++i) { std::snprintf(b, sizeof(b), "%02x", p[i]); s += b; }
    return s;
}

// Verify `expect` bytes at addr, then write `patch` bytes. prot_exec: restore R-X
// (code) vs R-- (rodata) afterwards. Returns true on success (and logs).
bool patch_site(const char* name, uintptr_t addr, const unsigned char* expect,
                const unsigned char* patch, std::size_t n, bool prot_exec) {
    void* p = reinterpret_cast<void*>(addr);
    if (std::memcmp(p, expect, n) != 0) {
        logw("patch %s: fingerprint mismatch at %p (got %s) — refusing", name, p,
             hexpre(reinterpret_cast<unsigned char*>(p), static_cast<int>(n < 8 ? n : 8)).c_str());
        return false;
    }
    if (!set_prot(p, n, PROT_READ | PROT_WRITE)) {
        loge("patch %s: mprotect RW failed", name);
        return false;
    }
    std::memcpy(p, patch, n);
    set_prot(p, n, prot_exec ? (PROT_READ | PROT_EXEC) : PROT_READ);
    if (prot_exec) __builtin___clear_cache(reinterpret_cast<char*>(addr), reinterpret_cast<char*>(addr + n));
    logi("patch %s: applied at %p (%zu bytes)", name, p, n);
    return true;
}

} // namespace

int apply_libmc5_http_patches(int http_port) {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) {
        logw("patch: libMC5.so not loaded");
        return 0;
    }
    int applied = 0;

    // 1. eve URL literal -> http://127.0.0.1:<port> (fits the 24-char original).
    {
        char repl[25];
        std::memset(repl, 0, sizeof(repl));
        int len = std::snprintf(repl, sizeof(repl), "http://127.0.0.1:%d", http_port);
        if (len > 0 && static_cast<std::size_t>(len) <= sizeof(kEveOriginal) - 1) {
            unsigned char expect[25];
            std::memset(expect, 0, sizeof(expect));
            std::memcpy(expect, kEveOriginal, sizeof(kEveOriginal) - 1); // 24 bytes, trailing nulls padded
            // Compare/patch the full 25-byte region (string + original null).
            if (patch_site("eve-url", base + kEveLiteralVaddr, expect,
                           reinterpret_cast<unsigned char*>(repl), 25, false))
                ++applied;
        } else {
            logw("patch eve-url: replacement too long for port %d", http_port);
        }
    }

    // 2. Neutralise the two http->https scheme rewriters (first instruction -> ret),
    //    so the pandora/federation URLs we return stay http.
    if (patch_site("rewrite-pandora", base + kRewritePandoraVaddr, kFnPrologue, kAarch64Ret, 4, true)) ++applied;
    if (patch_site("rewrite-federation", base + kRewriteFederationVaddr, kFnPrologue, kAarch64Ret, 4, true)) ++applied;

    logi("patch: %d/3 libMC5 http patches applied", applied);
    return applied;
}

#else // non-arm64

int apply_libmc5_http_patches(int /*http_port*/) {
    logw("patch: no libMC5 http-patch offsets for this ABI (arm64 only); https path unpatched");
    return 0;
}

#endif

} // namespace mc5
