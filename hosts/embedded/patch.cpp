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

// --- Entry-trace diagnostics -------------------------------------------------
// The post-login connection-error popup is NOT a Gaia result code: hooking the Gaia
// result setter 0xc35cf8 (prior round) logged nothing, and every federation op is 200.
// The verified mechanism (docs/research/02 §7) is that the Restrictions/legislation
// subsystem never initializes because compliancy.json is never fetched at boot. To pin
// the exact runtime path (and whether the compliancy fetch / RequestRestrictions / the
// restricted-mode signal ever fire), we install ENTRY-TRACE hooks on the decisive
// functions: a continuation trampoline that logs (label, x0, x1, caller-LR) and then
// runs the original intact. All target addresses below are REAL file vaddrs (verified
// via tools/re on the shipped libMC5.so) and their first 4 instructions are
// position-independent (checked), so relocating them into the trampoline is safe.
constexpr uintptr_t kTrProcessCompliancy    = 0x13961e8; // login FSM state5 -> compliancy eval
constexpr uintptr_t kTrRestrictionsInit     = 0x13c56c0; // Restrictions::Init (reads +0x100/+0x218)
constexpr uintptr_t kTrGetLegislationVersion= 0x13d3538; // reads Restrictions+0x178 (null => empty)
constexpr uintptr_t kTrRequestRestrictions  = 0x13a20b0; // post-age update path (dispatches slot4)
constexpr uintptr_t kTrComplianceFetch      = 0x13b9d68; // compliancy provider slot4 (the fetch!)
constexpr uintptr_t kTrRestrictedSignal     = 0x13d02e8; // ProcessRestrictions "restricted mode!"
constexpr uintptr_t kTrLegislationLoader    = 0x13d6fd8; // boot legislation loader (cache-read)

uintptr_t g_mc5_base = 0; // cached libMC5 base for LR->file-offset in trace logs

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

// Generic entry-trace callback: logs the function label, first two integer args and
// the caller return address (as a libMC5 file offset, so it maps straight back to a
// disassembly address). Called from the trampoline shim with the game's x0/x1/x30
// preserved. Runs on a normal game thread, so logi() (mutex + __android_log) is safe.
extern "C" void mc5_trace(const char* label, unsigned long long a0, unsigned long long a1,
                          unsigned long long lr) {
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    logi("trace: %s x0=0x%llx x1=0x%llx lr=+0x%llx", label, a0, a1, off);
}

// Specialised trace for functions whose x0 is the Restrictions object: also dumps the
// three gate fields we care about — +0x100 (Init full-branch gate), +0x178 (legislation
// JSON pointer; null => GetLegislationVersion returns JSON_NOT_INITIALIZED) and +0x218
// (IsLegislationInitialized atomic flag). x0 is a valid object at these entries; guard
// the null case only.
extern "C" void mc5_trace_restr(const char* label, unsigned long long thisptr,
                                unsigned long long /*a1*/, unsigned long long lr) {
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    if (thisptr == 0) { logi("trace: %s this=0 lr=+0x%llx", label, off); return; }
    unsigned int f100 = *reinterpret_cast<volatile unsigned int*>(thisptr + 0x100);
    unsigned long long p178 = *reinterpret_cast<volatile unsigned long long*>(thisptr + 0x178);
    unsigned int f218 = *reinterpret_cast<volatile unsigned char*>(thisptr + 0x218);
    logi("trace: %s this=0x%llx +0x100=0x%x +0x178=0x%llx +0x218=0x%x lr=+0x%llx",
         label, thisptr, f100, p178, f218, off);
}

// Reject relocating an instruction that is PC-relative (adr/adrp, b/bl, b.cond,
// cbz/cbnz, tbz/tbnz, ldr/ldrsw literal) — those break when moved into the trampoline.
bool reloc_safe(unsigned int w) {
    if ((w & 0x1f000000u) == 0x10000000u) return false; // ADR/ADRP
    if ((w & 0xfc000000u) == 0x14000000u) return false; // B
    if ((w & 0xfc000000u) == 0x94000000u) return false; // BL
    if ((w & 0xff000010u) == 0x54000000u) return false; // B.cond
    if ((w & 0x7e000000u) == 0x34000000u) return false; // CBZ/CBNZ
    if ((w & 0x7e000000u) == 0x36000000u) return false; // TBZ/TBNZ
    if ((w & 0x3b000000u) == 0x18000000u) return false; // LDR/LDRSW (literal)
    return true;
}

// Build an entry-trace trampoline for `vaddr` and patch its entry to jump there.
// Trampoline layout (validated with capstone): save x0-x8+x30; set up logger args
// (label, orig x0, orig x1, caller LR); call `logger`; restore; run the relocated
// original 16 bytes; jump to vaddr+16. `label` must be a static string (its pointer is
// embedded in the trampoline).
int install_trace_hook(const char* label, uintptr_t vaddr, void* logger) {
    if (g_mc5_base == 0) { logw("trace-hook %s: base unknown", label); return 0; }
    void* site = reinterpret_cast<void*>(vaddr);
    unsigned int orig[4];
    std::memcpy(orig, site, sizeof(orig));
    for (int i = 0; i < 4; ++i) {
        if (!reloc_safe(orig[i])) {
            logw("trace-hook %s: insn %d (0x%08x) at %p not relocatable — refusing", label, i, orig[i], site);
            return 0;
        }
    }
    long ps = sysconf(_SC_PAGESIZE);
    void* page = mmap(nullptr, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { loge("trace-hook %s: mmap failed", label); return 0; }
    unsigned int* w = static_cast<unsigned int*>(page);
    int n = 0;
    w[n++] = 0xD10183FF; // sub  sp, sp, #0x60
    w[n++] = 0xA90007E0; // stp  x0, x1, [sp]
    w[n++] = 0xA9010FE2; // stp  x2, x3, [sp, #0x10]
    w[n++] = 0xA90217E4; // stp  x4, x5, [sp, #0x20]
    w[n++] = 0xA9031FE6; // stp  x6, x7, [sp, #0x30]
    w[n++] = 0xA9047BE8; // stp  x8, x30, [sp, #0x40]
    int wi_label = n; w[n++] = 0x58000000;            // ldr  x0, #label  (imm19 patched below)
    w[n++] = 0xF94003E1; // ldr  x1, [sp]        (orig x0)
    w[n++] = 0xF94007E2; // ldr  x2, [sp, #8]    (orig x1)
    w[n++] = 0xF94027E3; // ldr  x3, [sp, #0x48] (orig lr)
    int wi_log = n;   w[n++] = 0x58000009;            // ldr  x9, #logger (imm19 patched below)
    w[n++] = 0xD63F0120; // blr  x9
    w[n++] = 0xA94007E0; // ldp  x0, x1, [sp]
    w[n++] = 0xA9410FE2; // ldp  x2, x3, [sp, #0x10]
    w[n++] = 0xA94217E4; // ldp  x4, x5, [sp, #0x20]
    w[n++] = 0xA9431FE6; // ldp  x6, x7, [sp, #0x30]
    w[n++] = 0xA9447BE8; // ldp  x8, x30, [sp, #0x40]
    w[n++] = 0x910183FF; // add  sp, sp, #0x60
    for (int i = 0; i < 4; ++i) w[n++] = orig[i];     // relocated original prologue
    w[n++] = 0x58000050; // ldr  x16, #8
    w[n++] = 0xD61F0200; // br   x16
    // 16-byte align the data pool, then: [cont target][label ptr][logger ptr].
    while ((n & 1) != 0) w[n++] = 0xD503201F; // nop pad to 8-byte boundary
    int di = n;
    unsigned long long* d = reinterpret_cast<unsigned long long*>(&w[di]);
    d[0] = static_cast<unsigned long long>(vaddr + 16);            // continuation target
    d[1] = reinterpret_cast<unsigned long long>(label);           // label string ptr
    d[2] = reinterpret_cast<unsigned long long>(logger);          // logger fn ptr
    // Patch the three ldr-literal loads. imm19 is in WORDS = (target_word - insn_word).
    // Data pool: d[0]=cont @word di, d[1]=label @word di+2, d[2]=logger @word di+4.
    int wi_cont = n - 2; // index of `ldr x16,#8`
    w[wi_cont]  = 0x58000000u | ((static_cast<unsigned int>(di     - wi_cont ) & 0x7ffffu) << 5) | 16; // ldr x16,d[0]
    w[wi_label] = 0x58000000u | ((static_cast<unsigned int>(di + 2 - wi_label) & 0x7ffffu) << 5) | 0;  // ldr x0, d[1]
    w[wi_log]   = 0x58000000u | ((static_cast<unsigned int>(di + 4 - wi_log  ) & 0x7ffffu) << 5) | 9;  // ldr x9, d[2]
    __builtin___clear_cache(reinterpret_cast<char*>(page), reinterpret_cast<char*>(page) + ps);

    // Patch the function entry: ldr x16,#8 ; br x16 ; <trampoline addr>.
    unsigned char entry[16] = {0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6};
    void* tramp = page;
    std::memcpy(entry + 8, &tramp, sizeof(tramp));
    if (!set_prot(site, sizeof(entry), PROT_READ | PROT_WRITE)) {
        loge("trace-hook %s: mprotect RW failed", label);
        return 0;
    }
    std::memcpy(site, entry, sizeof(entry));
    set_prot(site, sizeof(entry), PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + sizeof(entry));
    logi("trace-hook %s: installed at %p -> tramp %p", label, site, page);
    return 1;
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

int install_legislation_trace_hooks() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("trace-hooks: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    void* gen = reinterpret_cast<void*>(&mc5_trace);
    void* rst = reinterpret_cast<void*>(&mc5_trace_restr);
    int n = 0;
    // Restrictions object (x0) hooks use the restr logger (dumps +0x100/+0x178/+0x218).
    n += install_trace_hook("RestrictionsInit",      base + kTrRestrictionsInit,      rst);
    n += install_trace_hook("GetLegislationVersion", base + kTrGetLegislationVersion, rst);
    // Presence/path hooks use the generic logger (label + x0/x1 + caller).
    n += install_trace_hook("ProcessCompliancy",     base + kTrProcessCompliancy,     gen);
    n += install_trace_hook("RequestRestrictions",   base + kTrRequestRestrictions,   gen);
    n += install_trace_hook("ComplianceFetch(slot4)",base + kTrComplianceFetch,       gen);
    n += install_trace_hook("RestrictedSignal",      base + kTrRestrictedSignal,      gen);
    n += install_trace_hook("LegislationLoader",     base + kTrLegislationLoader,     gen);
    logi("trace-hooks: %d/7 legislation/restrictions entry hooks installed", n);
    return n;
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

int install_legislation_trace_hooks() {
    logw("trace-hooks: no offsets for this ABI (arm64 only)");
    return 0;
}

#endif

} // namespace mc5
