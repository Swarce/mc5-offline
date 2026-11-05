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
// Round 2 (legislation hooks) DISPROVED the legislation theory: on device
// Restrictions+0x178 is non-null and +0x218=1 (legislation initialises fine), and the
// compliancy fetch / RequestRestrictions / restricted-mode signal NEVER fire. The real
// symptom is a re-login loop (full re-auth every ~15s) after the HTTP chain succeeds.
// The Gaia online layer drives the UI through three Lua callbacks — onLoginCompleted,
// onLoginFailed(code) and onDisconnected — emitted by the bridge functions below (found
// by the 'onLoginCompleted'/'onLoginFailed'/'onDisconnected' string xrefs). onLoginFailed
// carries an error code in w2. We trace all three plus StartLogin to capture exactly what
// the game decides after login and what re-triggers the loop. Continuation trampolines
// log (label, x0, x1, x2, caller-LR) then run the original intact; all four targets have
// position-independent prologues (checked).
[[maybe_unused]] constexpr uintptr_t kTrOnLoginCompleted = 0x1354158; // Gaia -> Lua onLoginCompleted
[[maybe_unused]] constexpr uintptr_t kTrOnLoginFailed    = 0x1354418; // Gaia -> Lua onLoginFailed(code in w2)
[[maybe_unused]] constexpr uintptr_t kTrOnDisconnected   = 0x1353fb8; // Gaia -> Lua onDisconnected
constexpr uintptr_t kTrStartLogin       = 0xbcd410;  // OnlineFramework StartLogin (re-login trigger)

// Round 3 proved: HTTP chain completes every cycle, but NONE of the three Gaia->Lua
// terminal callbacks ever fire, and Lua re-calls StartLogin ~1/s. So the Gaia login
// state machine (pump 0xbcdab0) stalls after the HTTP chain without reaching the state
// that fires onLoginCompleted. The pump reads its state index from the global word at
// 0x1bc434c (idx = *0x1bc434c - 2; states 2..13). We hook the pump and log the state on
// each change to see exactly where it stops (state 5=compliancy, 9≈terminal).
constexpr uintptr_t kTrLoginFSM   = 0xbcdab0;   // Gaia login/update FSM pump
constexpr uintptr_t kFsmStateWord = 0x1bc434c;  // FSM state global (int)

// Round 5 (runtime campaign): the connected-gate (+0xEC) advanced the FSM to state 9 but
// did not fire onLoginCompleted; the popup persisted. +0xEC is set by the connection-state
// handler 0xb00508 (handler(this, msg); msg[0xe] u8, msg[0xf] u8) via setter 0x707a90.
// Hook 0xb00508 to learn whether this handler EVER fires and, via its caller-LR, what
// delivers the connection-state message (invisible to static analysis — bound callback).
[[maybe_unused]] constexpr uintptr_t kTrConnHandler = 0xb00508;  // connection-state handler (sets +0xEC path)

// Round 6: the popup's real trigger (static RE, docs/research/02 §12). The front-end
// manager's per-frame check 0xb30438 enters "connection lost" via 0xb30d80 when
//   conn = mgr->+0x10;  lost = !conn || (conn->u8[0x6c]==0 && conn->i32[0x98] != 2)
// i.e. connection SLOT 0 of the network-session object is not CONNECTED(2). Slots are
// set by 0x8cc370 (state=1 connecting, +0x90 handle) and 0x8cc3b0 (state=2 connected),
// filled via 0x8cc228 (local path: connecting then connected at once) or
// 0xae5928 -> 0x8ccdf0 (remote path with a handshake). Trace which path runs.
constexpr uintptr_t kTrEnterConnLost = 0xb30d80;  // front-end: enter connection-lost (state 1)
constexpr uintptr_t kTrSlotConnecting = 0x8cc370; // conn slot -> 1 (connecting)
constexpr uintptr_t kTrSlotConnected  = 0x8cc3b0; // conn slot -> 2 (connected)
constexpr uintptr_t kTrConnLocal      = 0x8cc228; // local/self path (connect + mark connected)
constexpr uintptr_t kTrConnRemote     = 0xae5928; // front-end remote connect (asio)
constexpr uintptr_t kTrConnHandshake  = 0x8ccdf0; // remote handshake -> mark connected

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

// The Gaia login "connected" gate: FUN @ 0x707ec0 = { return *(u8*)(this+0xEC); }.
// The login FSM's state-8 handler advances to the success terminal (state 9 ->
// onLoginCompleted) only when this returns non-zero; otherwise it diverts to the stuck
// state 11 and the Lua UI shows popupConnectionLost and re-logs-in ~1/s. The flag is set
// by a connection-state callback (0xb00508) that fires on a signal our loopback never
// delivers (not the alert stream). Since the game SHOULD believe it is online in our
// offline reimplementation, we force the gate true. Only the first instruction is
// overwritten (ldrb -> mov w0,#1); the trailing ret is kept. 8-byte fingerprint-guarded.
// See docs/research/02 §10.
constexpr uintptr_t kConnGateVaddr = 0x707ec0;
const unsigned char kConnGateFp[8] = {0x00, 0xb0, 0x43, 0x39,  // ldrb w0, [x0, #0xec]
                                      0xc0, 0x03, 0x5f, 0xd6}; // ret
const unsigned char kConnGatePatch[4] = {0x20, 0x00, 0x80, 0x52}; // mov w0, #1

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
                          unsigned long long a2, unsigned long long lr) {
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    logi("trace: %s x0=0x%llx x1=0x%llx x2=0x%llx(w2=%u) lr=+0x%llx",
         label, a0, a1, a2, static_cast<unsigned>(a2 & 0xffffffffu), off);
}

// Specialised trace for the Gaia login FSM pump: reads the FSM state global
// (base+kFsmStateWord) and logs only when it changes, giving a clean state-transition
// sequence (so we see the exact state the login stalls in). The pump runs often (per
// I/O completion + per frame), so on-change filtering keeps the log readable.
extern "C" void mc5_trace_fsm(const char* /*label*/, unsigned long long /*a0*/,
                              unsigned long long /*a1*/, unsigned long long /*a2*/,
                              unsigned long long lr) {
    static int last = -0x7fffffff;
    if (g_mc5_base == 0) return;
    int st = *reinterpret_cast<volatile int*>(g_mc5_base + kFsmStateWord);
    if (st == last) return;
    last = st;
    unsigned long long off = (lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    logi("fsm-state: %d (pump lr=+0x%llx)", st, off);
}

// Connection-state handler 0xb00508(this /*x0*/, msg /*x1*/): logs the message's byte
// fields ([0xe]=error?, [0xf]=connected-type?) and the caller-LR, which identifies the
// message source we could not resolve statically. msg may be null; guard it.
extern "C" void mc5_trace_conn(const char* /*label*/, unsigned long long /*x0*/,
                               unsigned long long msg, unsigned long long /*x2*/,
                               unsigned long long lr) {
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    unsigned e = 0, f = 0, a = 0, c = 0;
    if (msg) {
        a = *reinterpret_cast<volatile unsigned short*>(msg + 0x0a);
        c = *reinterpret_cast<volatile unsigned short*>(msg + 0x0c);
        e = *reinterpret_cast<volatile unsigned char*>(msg + 0x0e);
        f = *reinterpret_cast<volatile unsigned char*>(msg + 0x0f);
    }
    logi("conn-handler: msg=0x%llx [0xa]=%u [0xc]=%u [0xe]=%u [0xf]=%u lr=+0x%llx",
         msg, a, c, e, f, off);
}

// Front-end "enter connection-lost" 0xb30d80(mgr /*x0*/): dump exactly why — the
// network-session object (mgr+0x10) and its slot-0 state (+0x98, needs 2), the +0x6c
// override byte, slot-0 handle (+0x90), and the front-end state (mgr+0xB454).
extern "C" void mc5_trace_connlost(const char* /*label*/, unsigned long long mgr,
                                   unsigned long long /*x1*/, unsigned long long /*x2*/,
                                   unsigned long long lr) {
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    if (mgr == 0) { logi("conn-lost: mgr=0 lr=+0x%llx", off); return; }
    unsigned long long conn = *reinterpret_cast<volatile unsigned long long*>(mgr + 0x10);
    unsigned fe = *reinterpret_cast<volatile unsigned*>(mgr + 0xB454);
    if (conn == 0) { logi("conn-lost: mgr=0x%llx conn=NULL fe_state=%u lr=+0x%llx", mgr, fe, off); return; }
    int s0 = *reinterpret_cast<volatile int*>(conn + 0x98);
    int s1 = *reinterpret_cast<volatile int*>(conn + 0x9c);
    unsigned o6c = *reinterpret_cast<volatile unsigned char*>(conn + 0x6c);
    unsigned long long h0 = *reinterpret_cast<volatile unsigned long long*>(conn + 0x90);
    logi("conn-lost: mgr=0x%llx conn=0x%llx slot0_state=%d slot1_state=%d u8[0x6c]=%u slot0_handle=0x%llx fe_state=%u lr=+0x%llx",
         mgr, conn, s0, s1, o6c, h0, fe, off);
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
    w[n++] = 0xF9400BE3; // ldr  x3, [sp, #0x10] (orig x2)
    w[n++] = 0xF94027E4; // ldr  x4, [sp, #0x48] (orig lr)
    int wi_log = n;   w[n++] = 0x58000009;            // ldr  x9, #logger (imm19 patched below)
    w[n++] = 0xD63F0120; // blr  x9
    w[n++] = 0xA94007E0; // ldp  x0, x1, [sp]
    w[n++] = 0xA9410FE2; // ldp  x2, x3, [sp, #0x10]
    w[n++] = 0xA94217E4; // ldp  x4, x5, [sp, #0x20]
    w[n++] = 0xA9431FE6; // ldp  x6, x7, [sp, #0x30]
    w[n++] = 0xA9447BE8; // ldp  x8, x30, [sp, #0x40]
    w[n++] = 0x910183FF; // add  sp, sp, #0x60
    for (int i = 0; i < 4; ++i) w[n++] = orig[i];     // relocated original prologue
    int wi_cont = n; w[n++] = 0x58000050;             // ldr x16, #8 (imm19 patched below)
    w[n++] = 0xD61F0200; // br   x16
    // 16-byte align the data pool, then: [cont target][label ptr][logger ptr]. NB: capture
    // wi_cont at emit time above — computing it as n-2 after this pad is wrong when a pad
    // word is added (odd word count), which clobbers the br and falls through into data.
    while ((n & 1) != 0) w[n++] = 0xD503201F; // nop pad to 8-byte boundary
    int di = n;
    unsigned long long* d = reinterpret_cast<unsigned long long*>(&w[di]);
    d[0] = static_cast<unsigned long long>(vaddr + 16);            // continuation target
    d[1] = reinterpret_cast<unsigned long long>(label);           // label string ptr
    d[2] = reinterpret_cast<unsigned long long>(logger);          // logger fn ptr
    // Patch the three ldr-literal loads. imm19 is in WORDS = (target_word - insn_word).
    // Data pool: d[0]=cont @word di, d[1]=label @word di+2, d[2]=logger @word di+4.
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

int install_login_trace_hooks() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("trace-hooks: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    void* gen = reinterpret_cast<void*>(&mc5_trace);
    void* fsm = reinterpret_cast<void*>(&mc5_trace_fsm);
    int n = 0;
    // Rounds 3-5 hooks on onLogin*/onDisconnected/ConnHandler never fired and are dropped
    // to keep the log lean (definitions kept for reference).
    n += install_trace_hook("StartLogin",       base + kTrStartLogin,       gen);
    n += install_trace_hook("LoginFSM",         base + kTrLoginFSM,         fsm);
    n += install_trace_hook("EnterConnLost",    base + kTrEnterConnLost,    reinterpret_cast<void*>(&mc5_trace_connlost));
    n += install_trace_hook("SlotConnecting",   base + kTrSlotConnecting,   gen);
    n += install_trace_hook("SlotConnected",    base + kTrSlotConnected,    gen);
    n += install_trace_hook("ConnLocal",        base + kTrConnLocal,        gen);
    n += install_trace_hook("ConnRemote",       base + kTrConnRemote,       gen);
    n += install_trace_hook("ConnHandshake",    base + kTrConnHandshake,    gen);
    logi("trace-hooks: %d/8 login/connection hooks installed", n);
    return n;
}

int apply_libmc5_connected_gate() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("connected-gate: libMC5.so not loaded"); return 0; }
    void* site = reinterpret_cast<void*>(base + kConnGateVaddr);
    // Verify the full 2-instruction getter (ldrb;ret) before touching it.
    if (std::memcmp(site, kConnGateFp, sizeof(kConnGateFp)) != 0) {
        logw("connected-gate: fingerprint mismatch at %p (got %s) — refusing", site,
             hexpre(reinterpret_cast<unsigned char*>(site), 8).c_str());
        return 0;
    }
    // Overwrite only the ldrb (first 4 bytes) with `mov w0,#1`; keep the ret.
    if (!set_prot(site, 4, PROT_READ | PROT_WRITE)) { loge("connected-gate: mprotect RW failed"); return 0; }
    std::memcpy(site, kConnGatePatch, sizeof(kConnGatePatch));
    set_prot(site, 4, PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + 4);
    logi("connected-gate: login 'connected' check forced true at %p (ldrb -> mov w0,#1)", site);
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

int apply_libmc5_connected_gate() {
    logw("connected-gate: no offset for this ABI (arm64 only)");
    return 0;
}

int install_iris_log_hook() {
    logw("iris-log-hook: no offset for this ABI (arm64 only)");
    return 0;
}

int install_login_trace_hooks() {
    logw("trace-hooks: no offsets for this ABI (arm64 only)");
    return 0;
}

#endif

} // namespace mc5
