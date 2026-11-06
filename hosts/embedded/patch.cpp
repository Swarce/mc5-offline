#include "patch.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <string>
#include <sys/mman.h>
#include <sys/uio.h>
#include <thread>
#include <time.h>
#include <unistd.h>

#include "../../server/core/log.hpp"
#include "gothook.hpp"
#include "filter_tramp.hpp"
#include "item_dump.hpp"
#include <atomic>

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

// Gaia login SetLoginError(const std::string& code) @ 0xbcd618: a 16-byte leaf that
// assigns the global login-error string (0x1bc4360) via std::string::assign 0x40b838.
// A non-empty code makes the game state machine call loginMMError (0x831fd0), which shows
// "Failed to connect!" (string id 1733) or, every 3rd failure, "Servers are temporarily
// overloaded" (id 1942; a retry counter at online+0x438 picks the text), or "No Internet
// connection" (id 1938) for code "glni". Codes: glrer_<type>_<code>_<msg> (dataCenter
// re-check failed), glrec, gluvr, glgc_%d, gltv/glte/gltewc_%d_%d (180 s timeouts),
// gl<…>/gldah{d,b,v,np} (state-8 'connected' gate false), "compliancy error %d".
// We replace the leaf with a jump to a logger that then performs the same assignment, so
// the exact failing code reaches logcat. Diagnostic only: behaviour is unchanged.
// 16-byte fingerprint (mov x1,x0 ; adrp x0 ; add x0,x0,#0x360 ; b 0x40b838).
constexpr uintptr_t kSetLoginErrVaddr  = 0xbcd618;
constexpr uintptr_t kLoginErrStrVaddr  = 0x1bc4360; // global std::string (login error code)
constexpr uintptr_t kStrAssignVaddr    = 0x40b838;  // std::string::assign(const string&)
const unsigned char kSetLoginErrFp[16] = {0xe1, 0x03, 0x00, 0xaa, 0xa0, 0x7f, 0x00, 0xf0,
                                          0x00, 0x80, 0x0d, 0x91, 0x85, 0xf8, 0xe0, 0x17};

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

// Replacement for SetLoginError (see kSetLoginErrVaddr). Entered by `br` from the
// patched leaf, so x0 = &code (the original's argument) and x30 = the original caller's
// return address. Logs the code + caller, then does exactly what the original did.
extern "C" void* mc5_set_login_error(const void* code) {
    unsigned long long lr = reinterpret_cast<unsigned long long>(__builtin_return_address(0));
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    const char* data = "";
    std::size_t len = 0;
    if (code) {
        const unsigned char* p = static_cast<const unsigned char*>(code);
        if (p[0] & 1) { len = *reinterpret_cast<const std::size_t*>(p + 8);
                        data = *reinterpret_cast<const char* const*>(p + 16); }
        else          { len = p[0] >> 1; data = reinterpret_cast<const char*>(p + 1); }
        if (data == nullptr) { data = ""; len = 0; }
        if (len > 256) len = 256;
    }
    if (len) logw("login-error: SetLoginError(\"%.*s\") caller=+0x%llx", static_cast<int>(len), data, off);
    else     logi("login-error: cleared (caller=+0x%llx)", off);
    using AssignFn = void* (*)(void*, const void*);
    AssignFn assign = reinterpret_cast<AssignFn>(g_mc5_base + kStrAssignVaddr);
    return assign(reinterpret_cast<void*>(g_mc5_base + kLoginErrStrVaddr), code);
}

// --- Anubis (game_portal) connect diagnostics — docs/research/02 §15 ---------------
// The Anubis manager's error-suffix setter 0xc07fd8 is the same 16-byte leaf shape as
// SetLoginError: mov x1,x0 ; adrp x0 ; add x0,x0,#0x840 ; b 0x40b838 — it assigns the
// failure code ("awri", "atg_10_<ms>_D_<b0b3b1b4>", "hte_17_0", …) to the global
// std::string 0x1bc5840, which login state 8 later reports as "gl"+suffix.
constexpr uintptr_t kAnubisSuffixVaddr    = 0xc07fd8;
constexpr uintptr_t kAnubisSuffixStrVaddr = 0x1bc5840;
const unsigned char kAnubisSuffixFp[16] = {0xe1, 0x03, 0x00, 0xaa, 0xe0, 0x7d, 0x00, 0xd0,
                                           0x00, 0x00, 0x21, 0x91, 0x15, 0x0e, 0xe0, 0x17};

std::string read_cxx_string(const void* sp) {
    if (!sp) return std::string();
    const unsigned char* p = static_cast<const unsigned char*>(sp);
    const char* data;
    std::size_t len;
    if (p[0] & 1) { len = *reinterpret_cast<const std::size_t*>(p + 8);
                    data = *reinterpret_cast<const char* const*>(p + 16); }
    else          { len = p[0] >> 1; data = reinterpret_cast<const char*>(p + 1); }
    if (!data) return std::string();
    if (len > 256) len = 256;
    return std::string(data, len);
}

extern "C" void* mc5_anubis_set_suffix(const void* code) {
    unsigned long long lr = reinterpret_cast<unsigned long long>(__builtin_return_address(0));
    unsigned long long off = (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
    std::string s = read_cxx_string(code);
    if (!s.empty()) logw("anubis-suffix: '%s' (login error will read 'gl%s') caller=+0x%llx", s.c_str(), s.c_str(), off);
    else            logi("anubis-suffix: cleared (caller=+0x%llx)", off);
    using AssignFn = void* (*)(void*, const void*);
    AssignFn assign = reinterpret_cast<AssignFn>(g_mc5_base + kStrAssignVaddr);
    return assign(reinterpret_cast<void*>(g_mc5_base + kAnubisSuffixStrVaddr), code);
}

// Write the 16-byte "ldr x16,#8 ; br x16 ; <handler>" trampoline over a verified leaf.
int install_leaf_jump(const char* label, uintptr_t site_addr, const unsigned char* fp, void* handler) {
    void* site = reinterpret_cast<void*>(site_addr);
    if (std::memcmp(site, fp, 16) != 0) {
        logw("%s: fingerprint mismatch at %p (got %s) — refusing", label, site,
             hexpre(reinterpret_cast<unsigned char*>(site), 16).c_str());
        return 0;
    }
    unsigned char tramp[16] = {0x50, 0x00, 0x00, 0x58,  // ldr x16, #8
                               0x00, 0x02, 0x1f, 0xd6}; // br  x16
    std::memcpy(tramp + 8, &handler, sizeof(handler));
    if (!set_prot(site, sizeof(tramp), PROT_READ | PROT_WRITE)) { loge("%s: mprotect RW failed", label); return 0; }
    std::memcpy(site, tramp, sizeof(tramp));
    set_prot(site, sizeof(tramp), PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + sizeof(tramp));
    logi("%s: installed at %p", label, site);
    return 1;
}

// Poller: snapshots the Anubis FSM globals, the gate object's flag bytes and the
// controller connection state every 50 ms and logs a line only when something
// changed. Every read goes through process_vm_readv on our own pid, so a stale or
// unmapped pointer yields "unreadable" instead of a crash. Read-only.
constexpr uintptr_t kOnlinePtrVaddr  = 0x1bc62e8; // global behind GOT 0x1b9b0d8 (0x4e46a0 -> 0x511cb8)
constexpr uintptr_t kClockBaseVaddr  = 0x1bbe068; // u32 seconds base of the game clock 0x4e1c98
constexpr uintptr_t kLoginStateVaddr = 0x1bc434c;
constexpr uintptr_t kAnFsmVaddr      = 0x1bc5834;
constexpr uintptr_t kAnOpVaddr       = 0x1bc5838;
constexpr uintptr_t kAnIdleVaddr     = 0x1bc583c;
constexpr uintptr_t kAnRetryVaddr    = 0x1bc585c;
constexpr uintptr_t kAnGenVaddr      = 0x1bc5860;
constexpr uintptr_t kAnModeVaddr     = 0x1bc586c;
constexpr uintptr_t kAgeStateVaddr   = 0x1bc07a0; // age FSM 0x8ded40 state (read at 0x8ded78)
constexpr uintptr_t kMenuMgrVaddr    = 0x1bc1258; // menu manager global (GOT 0x1b9adc0)

template <typename T>
bool safe_read(uintptr_t addr, T& out) {
    if (addr < 0x1000) return false;
    iovec local{&out, sizeof(T)};
    iovec remote{reinterpret_cast<void*>(addr), sizeof(T)};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(sizeof(T));
}

struct AnubisSnap {
    int login = -1, fsm = -1, op = -1, retry = -1, gen = -1;
    int idle = -1, mode = -1;
    int f58 = -1, f59 = -1, f94 = -1, b0 = -1, b1 = -1, b2 = -1, b3 = -1, b4 = -1, b5 = -1;
    int ec = -1, f104 = -1, f105 = -1, f134 = -1;
    int cc_state = -1, cc_2920 = -1, cc_reason = -1;
    int age_state = -1, restr_done = -1, restr_cached = -1;
    int age_pending = -1, age_ok = -1, age_val = -1, age_connfail = -1;
    bool operator!=(const AnubisSnap& o) const { return std::memcmp(this, &o, sizeof(*this)) != 0; }
};

int rd8(uintptr_t a)  { unsigned char v; return safe_read(a, v) ? v : -1; }
int rd32(uintptr_t a) { int v; return safe_read(a, v) ? v : -1; }

void anubis_poll_loop(uintptr_t base) {
    AnubisSnap last;
    bool have_last = false, silent_logged = false;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        AnubisSnap s;
        s.login = rd32(base + kLoginStateVaddr);
        s.fsm = rd32(base + kAnFsmVaddr);
        s.op = rd32(base + kAnOpVaddr);
        s.idle = rd8(base + kAnIdleVaddr);
        s.retry = rd32(base + kAnRetryVaddr);
        s.gen = rd32(base + kAnGenVaddr);
        s.mode = rd8(base + kAnModeVaddr);
        uintptr_t online = 0, gate = 0, lobby = 0, cc = 0;
        // First-run age gate (§17): g_age_state 1 = waiting for the age/gender answer,
        // 10/11 = done (game state 0x26 -> 0x2b, the tutorial). online+0x110 = the
        // Restrictions answer arrived; online+0x118/+0x120 = cached restriction ids.
        s.age_state = rd32(base + kAgeStateVaddr);
        // ageObj = *(menuMgr + 8), menuMgr = *(base+0x1bc1258) (0x4e0470 via GOT 0x1b9adc0;
        // 0x4299b8). Fields written by the age callback 0x8de9e8: +9 popup pending,
        // +0xa ok, +0xc age, +0x10 connFail.
        {
            uintptr_t mm = 0, ao = 0;
            if (safe_read(base + kMenuMgrVaddr, mm) && mm && safe_read(mm + 8, ao) && ao) {
                s.age_pending = rd8(ao + 9);
                s.age_ok = rd8(ao + 0xa);
                s.age_val = rd32(ao + 0xc);
                s.age_connfail = rd8(ao + 0x10);
            }
        }
        if (safe_read(base + kOnlinePtrVaddr, online) && online) {
            s.restr_done = rd8(online + 0x110);
            uintptr_t vb = 0, ve = 0;
            if (safe_read(online + 0x118, vb) && safe_read(online + 0x120, ve))
                s.restr_cached = (ve >= vb && ve - vb < 0x1000) ? static_cast<int>((ve - vb) / 4) : -2;
        }
        if (online && safe_read(online + 0x1b8, gate) && gate) {
            s.f58 = rd8(gate + 0x58);   s.f59 = rd8(gate + 0x59);  s.f94 = rd32(gate + 0x94);
            s.b0 = rd8(gate + 0xb0);    s.b1 = rd8(gate + 0xb1);   s.b2 = rd8(gate + 0xb2);
            s.b3 = rd8(gate + 0xb3);    s.b4 = rd8(gate + 0xb4);   s.b5 = rd8(gate + 0xb5);
            s.ec = rd8(gate + 0xec);    s.f104 = rd8(gate + 0x104); s.f105 = rd8(gate + 0x105);
            s.f134 = rd8(gate + 0x134);
            if (safe_read(gate + 0x50, lobby) && lobby && safe_read(lobby + 0x28, cc) && cc) {
                s.cc_state = rd32(cc + 0x2870);
                s.cc_2920 = rd8(cc + 0x2920);
                s.cc_reason = rd32(cc + 0x29bc);
            }
            // TS silence (proves the server keepalive): game clock now - gate+0x3c.
            unsigned last_rx = 0, cbase = 0;
            timespec ts{};
            if (s.f58 == 1 && safe_read(gate + 0x3c, last_rx) && safe_read(base + kClockBaseVaddr, cbase) &&
                clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
                long now_ms = (static_cast<long>(ts.tv_sec) - static_cast<long>(cbase)) * 1000 + ts.tv_nsec / 1000000;
                long quiet = now_ms - static_cast<long>(last_rx);
                if (quiet > 8000 && !silent_logged) {
                    logw("anubis-poll: TS silent for %ldms (watchdog drops the link at 15000ms)", quiet);
                    silent_logged = true;
                } else if (quiet < 8000) {
                    silent_logged = false;
                }
            }
        }
        if (!have_last || s != last) {
            logi("anubis-poll: login=%d | anubis fsm=%d op=%d idle=%d retry=%d gen=%d mode=%d | "
                 "gate 58=%d 59=%d 94=%d b0=%d b1=%d b2=%d b3=%d b4=%d b5=%d EC=%d 104=%d 105=%d 134=%d | "
                 "cc state=%d 2920=%d reason=%d | age_state=%d restr_done=%d restr_cached=%d "
                 "ageObj pending=%d ok=%d age=%d connFail=%d",
                 s.login, s.fsm, s.op, s.idle, s.retry, s.gen, s.mode,
                 s.f58, s.f59, s.f94, s.b0, s.b1, s.b2, s.b3, s.b4, s.b5, s.ec, s.f104, s.f105, s.f134,
                 s.cc_state, s.cc_2920, s.cc_reason, s.age_state, s.restr_done, s.restr_cached,
                 s.age_pending, s.age_ok, s.age_val, s.age_connfail);
            last = s;
            have_last = true;
        }
    }
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

// ---- First-run age gate diagnostics (docs/research/02 §17) ----------------------
// The pre-tutorial "connection error" was the "ageLimit" notification popup: the age
// screen's Restrictions check (local, no HTTP) failed with 0x1c because compliancy.json
// had no <GameType> section. These hooks log every step of that chain so one device
// run shows whether the fix took and, if not, which step fails. Logging only; each
// site's first 16 bytes are compared to the shipped 6.0.12a bytes before patching.

// Bounded, crash-proof C-string read (process_vm_readv); non-printables become '.'.
std::string safe_cstr(unsigned long long addr, std::size_t max = 120) {
    if (addr < 0x1000) return addr ? "<bad>" : "<null>";
    static const std::size_t ps = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    std::string out;
    char buf[16];
    while (out.size() < max) {
        // Never let one read straddle a page boundary: a string whose NUL sits just
        // before an unmapped page must still be read in full.
        unsigned long long a = addr + out.size();
        std::size_t len = std::min<std::size_t>(sizeof(buf), ps - static_cast<std::size_t>(a & (ps - 1)));
        iovec local{buf, len};
        iovec remote{reinterpret_cast<void*>(a), len};
        ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (got <= 0) return out.empty() ? "<unreadable>" : out + "<unreadable>";
        for (ssize_t i = 0; i < got; ++i) {
            char ch = buf[i];
            if (ch == '\0') return out;
            out.push_back((ch >= 0x20 && ch < 0x7f) ? ch : '.');
            if (out.size() >= max) break;
        }
    }
    return out + "..";
}

unsigned long long lr_off(unsigned long long lr) {
    return (g_mc5_base && lr >= g_mc5_base) ? (lr - g_mc5_base) : lr;
}

// H1 0x8de9e8 age-gate callback (ok, age, connFail). ok=0 -> the ageLimit popup next
// frame (1733 "Failed to connect!" when connFail=1, else 4843-style age refusal).
extern "C" void mc5_trace_age_cb(const char*, unsigned long long ok, unsigned long long age,
                                 unsigned long long conn_fail, unsigned long long lr) {
    unsigned o = static_cast<unsigned>(ok & 0xff), cf = static_cast<unsigned>(conn_fail & 0xff);
    if (o) logi("age-gate: callback ok=1 age=%u connFail=%u lr=+0x%llx -> PASSED (tutorial next)",
                static_cast<unsigned>(age), cf, lr_off(lr));
    else   logw("age-gate: callback ok=0 age=%u connFail=%u lr=+0x%llx -> 'ageLimit' popup (%s)",
                static_cast<unsigned>(age), cf, lr_off(lr), cf ? "1733 Failed to connect!" : "age refusal");
}

// H2 0xc1c6c0 Restrictions completion (result, const std::vector<int>* ids).
extern "C" void mc5_trace_restr_done(const char*, unsigned long long result, unsigned long long vec,
                                     unsigned long long, unsigned long long lr) {
    std::string ids;
    int n = -1;
    uintptr_t b = 0, e = 0;
    if (safe_read(vec, b) && safe_read(vec + 8, e) && e >= b && e - b < 0x400) {
        n = static_cast<int>((e - b) / 4);
        for (int i = 0; i < n && i < 16; ++i) {
            int id = rd32(b + 4 * static_cast<uintptr_t>(i));
            char t[16];
            std::snprintf(t, sizeof(t), "%s0x%x", i ? "," : "", static_cast<unsigned>(id));
            ids += t;
        }
    }
    unsigned r = static_cast<unsigned>(result);
    if (r == 0 && n == 0) logi("age-gate: restrictions result=0 ids=[] lr=+0x%llx -> OK", lr_off(lr));
    else logw("age-gate: restrictions result=0x%x n=%d ids=[%s] lr=+0x%llx%s", r, n, ids.c_str(), lr_off(lr),
              r == 0x1c ? " (0x1c: empty/invalid restriction map — compliancy <GameType> section missing?)" : "");
}

// H3 0x13a2268 "Sending callback to game...result:" (result in w2).
extern "C" void mc5_trace_restr_cb(const char*, unsigned long long, unsigned long long,
                                   unsigned long long result, unsigned long long lr) {
    logi("age-gate: Restrictions 'Sending callback to game' result=0x%x lr=+0x%llx",
         static_cast<unsigned>(result), lr_off(lr));
}

// H4 0x901c18 native notification popup (message, tag, title): names every popup
// (ageLimit, loginMMError, mandatoryStateError, popupODRFailed, ...).
extern "C" void mc5_trace_popup(const char*, unsigned long long msg, unsigned long long tag,
                                unsigned long long title, unsigned long long lr) {
    logw("popup: tag='%s' title='%s' msg='%s' lr=+0x%llx", safe_cstr(tag, 48).c_str(),
         title ? safe_cstr(title, 64).c_str() : "", safe_cstr(msg).c_str(), lr_off(lr));
}

// H5 0xaa9ad0 popup_Connect(?, const char* a, const char* b, ?, bool w4): x0 is not
// read (0xaa9afc overwrites it with a singleton getter); x1/x2 are C strings compared
// against the literal "disconnected" (0xaa9f38/0xaa9f40).
extern "C" void mc5_trace_popup_connect(const char*, unsigned long long, unsigned long long x1,
                                        unsigned long long x2, unsigned long long lr) {
    logw("popup-connect: a='%s' b='%s' lr=+0x%llx", safe_cstr(x1, 64).c_str(),
         safe_cstr(x2, 64).c_str(), lr_off(lr));
}

// H7 0xc1c4e0 age submit (online, age, gender): gender is the raw UI value g.
extern "C" void mc5_trace_age_submit(const char* label, unsigned long long, unsigned long long age,
                                     unsigned long long gender, unsigned long long lr) {
    logi("age-gate: %s age=%u gender(ui)=%u lr=+0x%llx", label, static_cast<unsigned>(age),
         static_cast<unsigned>(gender), lr_off(lr));
}

// H6 0x13cfc68 RequestRestrictions (svc, age, gender_enc): 0xc1c4e0 encodes the UI
// gender as g+1, or 0 when g >= 3 (0xc1c5c8 cmp #3; csinc).
extern "C" void mc5_trace_age_req(const char* label, unsigned long long, unsigned long long age,
                                  unsigned long long gender, unsigned long long lr) {
    logi("age-gate: %s age=%u gender_enc=%u (=ui+1, 0 if ui>=3) lr=+0x%llx", label,
         static_cast<unsigned>(age), static_cast<unsigned>(gender), lr_off(lr));
}

// install_trace_hook with an exact 16-byte fingerprint check first.
int install_trace_hook_fp(const char* label, uintptr_t vaddr, const unsigned char (&fp)[16], void* logger) {
    void* site = reinterpret_cast<void*>(vaddr);
    if (std::memcmp(site, fp, 16) != 0) {
        logw("trace-hook %s: fingerprint mismatch at %p (got %s) — refusing", label, site,
             hexpre(reinterpret_cast<unsigned char*>(site), 16).c_str());
        return 0;
    }
    return install_trace_hook(label, vaddr, logger);
}

struct AgeHookSpec {
    const char* label;
    uintptr_t vaddr;
    unsigned char fp[16];
    void* logger;
};

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

int install_login_error_hook() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("login-error-hook: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    void* site = reinterpret_cast<void*>(base + kSetLoginErrVaddr);
    if (std::memcmp(site, kSetLoginErrFp, sizeof(kSetLoginErrFp)) != 0) {
        logw("login-error-hook: fingerprint mismatch at %p (got %s) — refusing", site,
             hexpre(reinterpret_cast<unsigned char*>(site), 16).c_str());
        return 0;
    }
    // ldr x16,#8 ; br x16 ; <8-byte handler address> — exactly the 16-byte leaf.
    unsigned char tramp[16] = {0x50, 0x00, 0x00, 0x58,  // ldr x16, #8
                               0x00, 0x02, 0x1f, 0xd6}; // br  x16
    void* handler = reinterpret_cast<void*>(&mc5_set_login_error);
    std::memcpy(tramp + 8, &handler, sizeof(handler));
    if (!set_prot(site, sizeof(tramp), PROT_READ | PROT_WRITE)) {
        loge("login-error-hook: mprotect RW failed");
        return 0;
    }
    std::memcpy(site, tramp, sizeof(tramp));
    set_prot(site, sizeof(tramp), PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + sizeof(tramp));
    logi("login-error-hook: installed at %p (Gaia login error codes -> logcat)", site);
    return 1;
}

int install_anubis_diag() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("anubis-diag: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    int n = install_leaf_jump("anubis-suffix-hook", base + kAnubisSuffixVaddr, kAnubisSuffixFp,
                              reinterpret_cast<void*>(&mc5_anubis_set_suffix));
    std::thread([base] { anubis_poll_loop(base); }).detach();
    logi("anubis-diag: suffix hook %s, state poller started (50 ms, logs on change)", n ? "installed" : "NOT installed");
    return n + 1;
}

int install_age_gate_diag() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("age-gate-diag: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    // Prologues read from the shipped 6.0.12a libMC5.so (all pass reloc_safe).
    const AgeHookSpec hooks[] = {
        {"AgeCallback", 0x8de9e8, {0xfc, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_age_cb)},
        {"RestrictionsDone", 0xc1c6c0, {0xff, 0x03, 0x01, 0xd1, 0xf5, 0x0b, 0x00, 0xf9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_restr_done)},
        {"RestrictionsSendCb", 0x13a2268, {0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_restr_cb)},
        {"PopupNotification", 0x901c18, {0xff, 0x83, 0x04, 0xd1, 0xfc, 0x67, 0x0d, 0xa9, 0xf8, 0x5f, 0x0e, 0xa9, 0xf6, 0x57, 0x0f, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_popup)},
        {"PopupConnect", 0xaa9ad0, {0xff, 0x03, 0x04, 0xd1, 0xfb, 0x53, 0x00, 0xf9, 0xfa, 0x67, 0x0b, 0xa9, 0xf8, 0x5f, 0x0c, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_popup_connect)},
        {"RequestRestrictions", 0x13cfc68, {0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_age_req)},
        {"AgeSubmit", 0xc1c4e0, {0xff, 0x03, 0x03, 0xd1, 0xf7, 0x43, 0x00, 0xf9, 0xf6, 0x57, 0x09, 0xa9, 0xf4, 0x4f, 0x0a, 0xa9},
         reinterpret_cast<void*>(&mc5_trace_age_submit)},
    };
    int n = 0;
    for (const auto& h : hooks) n += install_trace_hook_fp(h.label, base + h.vaddr, h.fp, h.logger);
    logi("age-gate-diag: %d/%zu hooks installed (age gate / restrictions / popups)", n,
         sizeof(hooks) / sizeof(hooks[0]));
    return n;
}

// --- Unlock-code item lists from the player's own in-memory game data ---------------
// Entry hooks on two game-thread TS builders: 0xc0e600 (0x53 redeem code: runs right
// before the code is sent, so the server has the lists when it answers) and 0xc0b948
// (0x16 loadout, sent after every login). The armory (A = *(base+0x1bbed40)) is filled
// synchronously at boot, before login (0x4e5c10), so it is complete at either hook.
// Reads go through process_vm_readv, so a bad pointer cannot fault the game.
namespace {
constexpr uintptr_t kArmoryGlobalVaddr = 0x1bbed40;  // armory singleton (getter 0x4e5f98)
constexpr uintptr_t kKillsigMgrVaddr   = 0x1bbed00;  // killsig manager (getter 0x4e5f58)
constexpr uintptr_t kSkillsMgrVaddr    = 0x1bbed08;  // skills manager (getter 0x4e5f68)
ItemSink g_item_sink = nullptr;
std::atomic<int> g_item_dump_tries{0};
std::atomic<bool> g_item_dump_done{false};

bool vm_read(std::uint64_t addr, void* out, std::size_t n) {
    if (addr < 0x1000 || n == 0) return n == 0;
    iovec local{out, n};
    iovec remote{reinterpret_cast<void*>(addr), n};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(n);
}

extern "C" void mc5_item_dump_hook(const char* label, unsigned long long, unsigned long long,
                                   unsigned long long, unsigned long long) {
    if (g_item_dump_done.load() || !g_item_sink || g_item_dump_tries.fetch_add(1) >= 3) return;
    std::uint64_t A = 0, M = 0, S = 0;
    vm_read(g_mc5_base + kArmoryGlobalVaddr, &A, 8);
    vm_read(g_mc5_base + kKillsigMgrVaddr, &M, 8);
    vm_read(g_mc5_base + kSkillsMgrVaddr, &S, 8);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    itemdump::Result r = itemdump::dump(vm_read, A, M, S);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long us = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000;
    for (const auto& n : r.notes) logi("item-dump: %s", n.c_str());
    logi("item-dump: at %s, armory=0x%llx killsigs=0x%llx, %zu groups in %ld us", label,
         static_cast<unsigned long long>(A), static_cast<unsigned long long>(M), r.groups.size(), us);
    if (r.groups.count("weapons")) g_item_dump_done.store(true);
    if (!r.groups.empty()) g_item_sink(r.groups, label);
}
} // namespace

int install_entry_hook(const char* label, uintptr_t vaddr, const unsigned char (&fp)[16], void* logger) {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("entry-hook %s: libMC5.so not loaded", label); return 0; }
    g_mc5_base = base;
    return install_trace_hook_fp(label, base + vaddr, fp, logger);
}

uintptr_t libmc5_base() { return so_base("libMC5.so"); }

int install_filter_hook(const char* label, uintptr_t vaddr, const unsigned char (&fp)[16], void* filter) {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("filter-hook %s: libMC5.so not loaded", label); return 0; }
    g_mc5_base = base;
    void* site = reinterpret_cast<void*>(base + vaddr);
    if (std::memcmp(site, fp, 16) != 0) {
        logw("filter-hook %s: fingerprint mismatch at %p (got %s) — refusing", label, site,
             hexpre(reinterpret_cast<unsigned char*>(site), 16).c_str());
        return 0;
    }
    std::uint32_t orig[4];
    std::memcpy(orig, site, sizeof(orig));
    long ps = sysconf(_SC_PAGESIZE);
    void* page = mmap(nullptr, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { loge("filter-hook %s: mmap failed", label); return 0; }
    if (!build_filter_tramp(static_cast<std::uint32_t*>(page), orig, base + vaddr + 16,
                            reinterpret_cast<std::uint64_t>(filter))) {
        logw("filter-hook %s: prologue at %p not relocatable — refusing", label, site);
        munmap(page, ps);
        return 0;
    }
    __builtin___clear_cache(reinterpret_cast<char*>(page), reinterpret_cast<char*>(page) + ps);
    unsigned char entry[16] = {0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6}; // ldr x16,#8 ; br x16
    std::memcpy(entry + 8, &page, sizeof(page));
    if (!set_prot(site, sizeof(entry), PROT_READ | PROT_WRITE)) {
        loge("filter-hook %s: mprotect RW failed", label);
        munmap(page, ps);
        return 0;
    }
    std::memcpy(site, entry, sizeof(entry));
    set_prot(site, sizeof(entry), PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + sizeof(entry));
    logi("filter-hook %s: installed at %p -> tramp %p", label, site, page);
    return 1;
}

int install_item_dump_hooks(ItemSink sink) {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("item-dump: libMC5.so not loaded"); return 0; }
    g_mc5_base = base;
    g_item_sink = sink;
    static const unsigned char kRedeemFp[16] = {0xfc, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9,
                                                0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91};
    static const unsigned char kLoadoutFp[16] = {0xfc, 0x0f, 0x1b, 0xf8, 0xf8, 0x5f, 0x01, 0xa9,
                                                 0xf6, 0x57, 0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9};
    int n = install_trace_hook_fp("RedeemSend(0x53)", base + 0xc0e600, kRedeemFp,
                                  reinterpret_cast<void*>(&mc5_item_dump_hook));
    n += install_trace_hook_fp("LoadoutSend(0x16)", base + 0xc0b948, kLoadoutFp,
                               reinterpret_cast<void*>(&mc5_item_dump_hook));
    logi("item-dump: %d/2 hooks installed (lists are read on the game thread before 0x53/0x16)", n);
    return n;
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

// Host self-registration 0xae3a70 adds the LOCAL player (the match host) to the player
// table with state 4 (spectator/host): at 0xae3aa4 `mov w8,#4` -> stored as the AddPlayer
// state arg. State != 1 makes AddPlayer force the stored id to 0xffff and the player a
// view-less spectator (black screen, no soldier/camera). Patch the single instruction to
// `mov w8,#1` so the host joins as a real, id-addressable, spawning participant (both are
// ORR-immediate encodings; only one byte differs). Authority is independent (conn+0x6c),
// so the host role is unaffected. See docs/research/06 and the realplay RE. arm64 only.
constexpr uintptr_t kHostStateVaddr = 0xae3aa4;
const unsigned char kHostStateFp[4] = {0xe8, 0x03, 0x1e, 0x32};    // mov w8, #4
const unsigned char kHostStatePatch[4] = {0xe8, 0x03, 0x00, 0x32}; // mov w8, #1

int apply_libmc5_host_player_state() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("host-player-state: libMC5.so not loaded"); return 0; }
    void* site = reinterpret_cast<void*>(base + kHostStateVaddr);
    if (std::memcmp(site, kHostStateFp, sizeof(kHostStateFp)) != 0) {
        logw("host-player-state: fingerprint mismatch at %p (got %s) — refusing", site,
             hexpre(reinterpret_cast<unsigned char*>(site), 4).c_str());
        return 0;
    }
    if (!set_prot(site, 4, PROT_READ | PROT_WRITE)) { loge("host-player-state: mprotect RW failed"); return 0; }
    std::memcpy(site, kHostStatePatch, sizeof(kHostStatePatch));
    set_prot(site, 4, PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(site), reinterpret_cast<char*>(site) + 4);
    logi("host-player-state: local host joins as a real player at %p (mov w8,#4 -> #1)", site);
    return 1;
}

// Null-safe replacement for the current-weapon accessor 0x700ea0:
//   orig: loadout=x0; return loadout->vec[*(int*)(loadout+0x3e8)] (null-safe only on the
//   vector, NOT on loadout itself) -> SIGSEGV at 0x160 when a participant's loadout
//   (slotobj+0x4d0) is NULL. We fully replace it (leaf jump, no relocation) with a version
//   that returns NULL for a NULL loadout; every caller already handles a NULL weapon.
extern "C" void* mc5_safe_current_weapon(void* loadout) {
    if (!loadout) return nullptr;
    char* p = reinterpret_cast<char*>(loadout);
    std::uintptr_t begin = *reinterpret_cast<std::uintptr_t*>(p + 0x160);
    std::uintptr_t end = *reinterpret_cast<std::uintptr_t*>(p + 0x168);
    if (end == begin) return nullptr;
    int idx = *reinterpret_cast<int*>(p + 0x3e8);
    if (idx < 0) return nullptr;
    long count = static_cast<long>(end - begin) >> 5; // 0x20-byte elements
    if (static_cast<long>(idx) >= count) return nullptr;
    return *reinterpret_cast<void**>(begin + (static_cast<std::uintptr_t>(idx) << 5));
}

int apply_libmc5_weapon_accessor_guard() {
    uintptr_t base = so_base("libMC5.so");
    if (base == 0) { logw("weapon-accessor-guard: libMC5.so not loaded"); return 0; }
    static const unsigned char fp[16] = {0x08, 0x24, 0x56, 0xa9, 0x2a, 0x01, 0x08, 0xeb,
                                         0x20, 0x01, 0x00, 0x54, 0x09, 0xe8, 0x83, 0xb9};
    return install_leaf_jump("weapon-accessor-guard(0x700ea0)", base + 0x700ea0, fp,
                             reinterpret_cast<void*>(&mc5_safe_current_weapon));
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

// Level-up rewards accessor 0x628af8(cfg, level): returns &cfg->rewards[level] (a
// vector<vector<{u32 item, i32 qty}>> at cfg+0x5f8, element 0x18), or the table's
// begin for level <= 0 or out of range. The table is sized ONLY by the config parser
// (0x614c78 from game["_level_up_rewards"]), so until a TCP_Config with "game" has
// been applied begin == NULL and the three callers (Profile->stats 0x95cb20, level-up
// popups 0x941738 / 0xa3e820) do `ldp x8,x9,[x0]` on NULL: the Profile->stats crash
// at 0x95e6ec. The server now sends that config (meta.cpp); this patch is the
// belt-and-braces: an EMPTY table returns &cfg->table itself ({NULL,NULL}), so the
// callers' existing `cmp x9,x8; b.eq` skips the loop. Non-empty tables behave exactly
// as before (level <= 0 still yields begin via the unsigned csel). 68 bytes, the whole
// function, fingerprint-verified:
//   ldr x9,[x0,#0x5f8] ; cbz x9,+0x38 ; <original body> ; add x0,x0,#0x5f8 ; ret
constexpr uintptr_t kLevelUpRewardsVaddr = 0x628af8;
const unsigned char kLevelUpRewardsFp[68] = {
    0x3f, 0x00, 0x00, 0x71, 0xcd, 0x01, 0x00, 0x54, 0x08, 0x00, 0x43, 0xf9, 0xea, 0xf3, 0x01, 0xb2,
    0x09, 0xfc, 0x42, 0xf9, 0x6a, 0x55, 0x95, 0xf2, 0xeb, 0x07, 0x1d, 0x32, 0x08, 0x01, 0x09, 0xcb,
    0x2b, 0x24, 0x2b, 0x9b, 0x08, 0xfd, 0x43, 0x93, 0x08, 0x7d, 0x0a, 0x9b, 0x2a, 0x7c, 0x40, 0x93,
    0x1f, 0x01, 0x0a, 0xeb, 0x60, 0x81, 0x89, 0x9a, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0xfc, 0x42, 0xf9,
    0xc0, 0x03, 0x5f, 0xd6};
const unsigned char kLevelUpRewardsPatch[68] = {
    0x09, 0xfc, 0x42, 0xf9, 0xc9, 0x01, 0x00, 0xb4, 0x08, 0x00, 0x43, 0xf9, 0xea, 0xf3, 0x01, 0xb2,
    0x09, 0xfc, 0x42, 0xf9, 0x6a, 0x55, 0x95, 0xf2, 0xeb, 0x07, 0x1d, 0x32, 0x08, 0x01, 0x09, 0xcb,
    0x2b, 0x24, 0x2b, 0x9b, 0x08, 0xfd, 0x43, 0x93, 0x08, 0x7d, 0x0a, 0x9b, 0x2a, 0x7c, 0x40, 0x93,
    0x1f, 0x01, 0x0a, 0xeb, 0x60, 0x81, 0x89, 0x9a, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0xe0, 0x17, 0x91,
    0xc0, 0x03, 0x5f, 0xd6};

int apply_levelup_rewards_guard() {
    uintptr_t base = so_base("libMC5.so");
    if (!base) { logw("levelup-rewards-guard: libMC5 base not found"); return 0; }
    bool ok = patch_site("levelup-rewards-guard", base + kLevelUpRewardsVaddr, kLevelUpRewardsFp,
                         kLevelUpRewardsPatch, sizeof(kLevelUpRewardsPatch), true);
    if (ok) logi("levelup-rewards-guard: 0x628af8 returns an empty range for an unsized table "
                 "(Profile->stats / level-up popups no longer dereference NULL)");
    return ok ? 1 : 0;
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

int apply_libmc5_host_player_state() {
    logw("host-player-state: arm64 only");
    return 0;
}

int apply_libmc5_weapon_accessor_guard() {
    logw("weapon-accessor-guard: arm64 only");
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

int install_login_error_hook() {
    logw("login-error-hook: no offset for this ABI (arm64 only)");
    return 0;
}

int install_anubis_diag() {
    logw("anubis-diag: no offsets for this ABI (arm64 only)");
    return 0;
}

int install_age_gate_diag() {
    logw("age-gate-diag: no offsets for this ABI (arm64 only)");
    return 0;
}

int apply_levelup_rewards_guard() {
    logw("levelup-rewards-guard: no offset for this ABI (arm64 only)");
    return 0;
}

int install_item_dump_hooks(ItemSink) {
    logw("item-dump: no offsets for this ABI (arm64 only)");
    return 0;
}

int install_entry_hook(const char* label, uintptr_t, const unsigned char (&)[16], void*) {
    logw("entry-hook %s: arm64 only", label);
    return 0;
}

int install_filter_hook(const char* label, uintptr_t, const unsigned char (&)[16], void*) {
    logw("filter-hook %s: arm64 only", label);
    return 0;
}

uintptr_t libmc5_base() { return 0; }

#endif

} // namespace mc5
