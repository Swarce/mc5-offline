#include "patch.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
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

const char kEveOriginal[] = "https://eve.gameloft.com";       // 24 chars

// The Gaia online layer logs its boot/discovery through an "[IRISCfgProvider]"
// logger (FUN @ 0x1386098): void log(ctx /*x0*/, std::string& msg /*x1*/). It only
// emits when ctx->logger (ctx+0x18) is non-null, which it is NOT in the shipped
// release build — so the discovery trace ("Getting URLs from Eve", "Discovered
// Pandora URL: …", "Failed to parse Pandora URL from Eve response", "Eve URLs
// request failed: HTTP N", "Failed to find preferred datacenter", …) never reaches
// logcat. We replace this function (a no-op in release) with a trampoline to our
// own handler that reads the message string and tees it to logcat, so the game
// itself tells us exactly which discovery step fails. Its real address is NOT the
// decompiler's 0x1486098: the decomp's 0x148xxxx code addresses are shifted
// ~+0x100000 from this build; 0x1386098 is the real entry (verified by the
// "[IRISCfgProvider]" string xref and the prologue fingerprint below).
constexpr uintptr_t kIrisLogVaddr = 0x1386098;
const unsigned char kIrisLogFp[16] = {0xff, 0x03, 0x01, 0xd1, 0xf3, 0x13, 0x00, 0xf9,
                                      0xfd, 0x7b, 0x03, 0xa9, 0xfd, 0xc3, 0x00, 0x91};

// asio::ssl::detail::engine::verify_callback_function(int, X509_STORE_CTX*) — the
// callback OpenSSL invokes to accept/reject the server cert. Exported (WEAK), so
// resolved by symbol at runtime; its prologue is the fingerprint, and the patch
// makes it `return 1` (accept any cert). kAsioVerifyVaddr is the fallback offset.
const char kAsioVerifySym[] =
    "_ZN4asio3ssl6detail6engine24verify_callback_functionEiP17x509_store_ctx_st";
const unsigned char kAsioVerifyFp[8] = {0xf5, 0x0f, 0x1d, 0xf8, 0xf4, 0x4f, 0x01, 0xa9};
const unsigned char kAsioVerifyAccept[8] = {0x20, 0x00, 0x80, 0x52,  // mov w0, #1
                                            0xc0, 0x03, 0x5f, 0xd6}; // ret
constexpr uintptr_t kAsioVerifyVaddr = 0x1252c70;

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

// Our replacement for the IRIS config-provider logger. Called with the game's
// original args intact: x0 = logger context (unused), x1 = &std::string message.
// Reads the libc++ std::string (default layout: LSB of byte 0 = is-long flag) and
// tees it to logcat. Runs on a normal game thread (not a signal handler), so the
// mutex/vsnprintf inside logi() are safe. Replacing the whole function is safe
// because the original is a no-op in release (its sink pointer is null).
void mc5_iris_log_tee(void* /*ctx*/, const void* msg) {
    if (msg == nullptr) return;
    const unsigned char* p = static_cast<const unsigned char*>(msg);
    const char* data;
    std::size_t len;
    if (p[0] & 1) { // long representation
        len = *reinterpret_cast<const std::size_t*>(p + 8);
        data = *reinterpret_cast<const char* const*>(p + 16);
    } else {        // short representation (chars inline)
        len = p[0] >> 1;
        data = reinterpret_cast<const char*>(p + 1);
    }
    if (data == nullptr) return;
    if (len > 1024) len = 1024; // cap defensively
    logi("gaia[IRIS]: %.*s", static_cast<int>(len), data);
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

    // NB: the former "rewrite-pandora"/"rewrite-federation" patches (RET at
    // 0xc85db0/0xc86020) were removed. Those offsets are real functions doing
    // std::string work, not the http->https scheme rewriter — the actual URL
    // normaliser is FUN_01488b50 (scheme chosen by port: 443->https, 80->http,
    // other->http keep-port), which the eve-config URLs do NOT pass through (the
    // pandora value is used as returned). Neutralising two misidentified functions
    // right before pandora discovery was a prime suspect for breaking it, so we no
    // longer touch them; any stray Gameloft host is still caught by the connect/
    // getaddrinfo redirect.
    logi("patch: %d/1 libMC5 http patches applied", applied);
    return applied;
}

int install_iris_log_hook() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("iris-log-hook: libMC5.so not loaded"); return 0; }
    void* site = reinterpret_cast<void*>(base + kIrisLogVaddr);
    if (std::memcmp(site, kIrisLogFp, sizeof(kIrisLogFp)) != 0) {
        logw("iris-log-hook: fingerprint mismatch at %p (got %s) — refusing", site,
             hexpre(reinterpret_cast<unsigned char*>(site), 8).c_str());
        return 0;
    }
    // Trampoline: ldr x16,#8 ; br x16 ; <8-byte absolute handler address>.
    unsigned char tramp[16] = {0x50, 0x00, 0x00, 0x58,  // ldr x16, #8
                               0x00, 0x02, 0x1f, 0xd6}; // br  x16
    void* handler = reinterpret_cast<void*>(&mc5_iris_log_tee);
    std::memcpy(tramp + 8, &handler, sizeof(handler));
    if (!set_prot(site, sizeof(tramp), PROT_READ | PROT_WRITE)) {
        loge("iris-log-hook: mprotect RW failed");
        return 0;
    }
    std::memcpy(site, tramp, sizeof(tramp));
    set_prot(site, sizeof(tramp), PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + sizeof(tramp));
    logi("iris-log-hook: installed at %p (Gaia discovery trace -> logcat)", site);
    return 1;
}

int apply_libmc5_tls_bypass() {
    // Resolve the exported callback by symbol (robust); fall back to vaddr+base.
    uintptr_t addr = 0;
    if (void* h = dlopen("libMC5.so", RTLD_NOLOAD | RTLD_NOW)) {
        addr = reinterpret_cast<uintptr_t>(dlsym(h, kAsioVerifySym));
        dlclose(h);
    }
    if (addr == 0) {
        uintptr_t base = so_base("libMC5.so");
        if (base) addr = base + kAsioVerifyVaddr;
        logd("tls-bypass: dlsym miss, using vaddr fallback (base=%p)", reinterpret_cast<void*>(base));
    }
    if (addr == 0) { logw("tls-bypass: asio verify callback not found"); return 0; }
    bool ok = patch_site("asio-verify-accept", addr, kAsioVerifyFp, kAsioVerifyAccept, 8, true);
    if (ok) logi("tls-bypass: server-cert verification neutralised (asio verify -> accept)");
    return ok ? 1 : 0;
}

#else // non-arm64

int apply_libmc5_http_patches(int /*http_port*/) {
    logw("patch: no libMC5 http-patch offsets for this ABI (arm64 only); https path unpatched");
    return 0;
}

int apply_libmc5_tls_bypass() {
    logw("tls-bypass: no asio verify offset for this ABI (arm64 only)");
    return 0;
}

int install_iris_log_hook() {
    logw("iris-log-hook: no offset for this ABI (arm64 only)");
    return 0;
}

#endif

} // namespace mc5
