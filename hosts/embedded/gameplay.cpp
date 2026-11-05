// gameplay.cpp — game-thread work the server asks for: gameplay cheat bytes, the
// campaign zone table walk, and the experimental local bot match.
//
// Everything runs from an entry hook on the TS config pump 0x5f5128, which the app
// update 0x4eed80 calls once per frame on the game (main) thread, so nothing races the
// game's own data. The server thread only sets atomics. Every address and the game's
// own call sequence we reuse are fingerprint-checked; all reads go through
// process_vm_readv; anything unexpected is logged and skipped.
//
// Research: docs/research/06-zones-cheats-bots.md. libMC5 6.0.12a arm64 only.
// C++17.
#include "gameplay.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <sys/uio.h>
#include <unistd.h>

#include "../../server/core/log.hpp"
#include "patch.hpp"

namespace mc5 {
namespace gameplay {

namespace {

ServerContext* g_ctx = nullptr;
uintptr_t g_base = 0;
bool g_seq_ok = false;      // the local-match call sequence matched byte for byte
bool g_settings_ok = false; // the settings getter matched
bool g_camp_ok = false;     // the campaign getter matched

std::atomic<bool> g_cheats_pending{false};
std::atomic<int> g_cheat_bits{0}; // bit0 god, bit1 ammo, bit2 medkits
std::atomic<bool> g_walk_pending{false};
std::chrono::steady_clock::time_point g_walk_at{};
std::mutex g_walk_mu;
std::atomic<int> g_botmatch_pending{0}; // bot count requested (0 = none)
std::atomic<int> g_bots_armed{0};       // bots to set on the next bot manager seen
std::atomic<uintptr_t> g_last_bm{0};

bool rd(uintptr_t a, void* out, std::size_t n) {
    if (a < 0x1000) return false;
    iovec l{out, n}, r{reinterpret_cast<void*>(a), n};
    return process_vm_readv(getpid(), &l, 1, &r, 1, 0) == static_cast<ssize_t>(n);
}
template <class T> bool rdv(uintptr_t a, T& v) { return rd(a, &v, sizeof(T)); }

bool bytes_match(uintptr_t vaddr, const unsigned char* exp, std::size_t n) {
    std::vector<unsigned char> got(n);
    return rd(g_base + vaddr, got.data(), n) && std::memcmp(got.data(), exp, n) == 0;
}

// --- gameplay cheat bytes ---------------------------------------------------
// The game's settings block: getter 0x4e3498 = adrp/ldr of .bss 0x1bbdf28. Byte [0]
// godMode, [5] infiniteAmmo, [6] infiniteMedkits (debug options 0x1d/0x20/0x21 in
// G:0x9eb990, saved to /settings_new.dat by G:0x5e34a8).
constexpr uintptr_t kSettingsGetter = 0x4e3498;
constexpr uintptr_t kSettingsPtr = 0x1bbdf28;
const unsigned char kSettingsGetterFp[12] = {0xc8, 0xb6, 0x00, 0xd0, 0x00, 0x95, 0x47, 0xf9, 0xc0, 0x03, 0x5f, 0xd6};

void apply_cheats_now() {
    int bits = g_cheat_bits.load();
    uintptr_t s = 0;
    if (!g_settings_ok || !rdv(g_base + kSettingsPtr, s) || s < 0x1000) {
        logw("[cheats] settings block not available (fingerprint %s, ptr 0x%llx)", g_settings_ok ? "ok" : "MISMATCH",
             static_cast<unsigned long long>(s));
        return;
    }
    unsigned char cur[8];
    if (!rd(s, cur, sizeof(cur))) { logw("[cheats] settings block unreadable"); return; }
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(s);
    p[0] = (bits & 1) ? 1 : 0;
    p[5] = (bits & 2) ? 1 : 0;
    p[6] = (bits & 4) ? 1 : 0;
    logi("[cheats] settings@0x%llx godMode=%d infiniteAmmo=%d infiniteMedkits=%d (was %d/%d/%d)",
         static_cast<unsigned long long>(s), bits & 1, (bits >> 1) & 1, (bits >> 2) & 1, cur[0], cur[5], cur[6]);
}

// --- campaign zone table ----------------------------------------------------
// camp = *(*(base+0x1b9aed8)) (getter 0x4e45c0). UI zone count Z = n-4 with n the
// zone table entries (*(camp+0xb8): vector at +0x98, stride 0x218; 0x8e2810).
// Entries at camp+0x30..+0x38, stride 0x48: +0 zone, +4 type (0 = story), +8 block;
// block +0x80 node count, +0x88 node array; node +0x38 id (FNV-1a of the level name),
// +0x6a completed (0x8e2d60 -> 0x64f5f8 -> 0x5c2d30 / 0x4f85b0).
constexpr uintptr_t kCampGetter = 0x4e45c0;
constexpr uintptr_t kCampGot = 0x1b9aed8;
const unsigned char kCampGetterFp[16] = {0xa8, 0xb5, 0x00, 0xd0, 0x08, 0x6d, 0x47, 0xf9,
                                         0x00, 0x01, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6};

bool walk_zones(std::map<int, std::vector<std::uint32_t>>& story, int& Z, std::string& why) {
    uintptr_t got = 0, camp = 0, t = 0, b98 = 0, ba0 = 0, beg = 0, end = 0;
    if (!g_camp_ok) { why = "campaign getter fingerprint mismatch"; return false; }
    if (!rdv(g_base + kCampGot, got) || !rdv(got, camp) || camp < 0x1000) { why = "no campaign object"; return false; }
    if (!rdv(camp + 0xb8, t) || t < 0x1000 || !rdv(t + 0x98, b98) || !rdv(t + 0xa0, ba0) || ba0 < b98 ||
        (ba0 - b98) % 0x218 != 0) { why = "zone table not ready"; return false; }
    long n = static_cast<long>((ba0 - b98) / 0x218);
    if (n < 5 || n > 64) { why = "zone table size " + std::to_string(n); return false; }
    Z = static_cast<int>(n - 4);
    if (!rdv(camp + 0x30, beg) || !rdv(camp + 0x38, end) || end < beg || (end - beg) % 0x48 != 0 ||
        (end - beg) / 0x48 > 512) { why = "entry list not ready"; return false; }
    story.clear();
    for (uintptr_t e = beg; e < end; e += 0x48) {
        std::int32_t zone = -1, type = -1, cnt = 0;
        uintptr_t blk = 0, arr = 0;
        if (!rdv(e, zone) || !rdv(e + 4, type) || !rdv(e + 8, blk)) { why = "entry unreadable"; return false; }
        if (type != 0) continue;
        if (zone < 0 || zone >= Z) { why = "entry zone " + std::to_string(zone) + " out of range"; return false; }
        if (!rdv(blk + 0x80, cnt) || cnt <= 0 || cnt > 64 || !rdv(blk + 0x88, arr)) { why = "block unreadable"; return false; }
        for (std::int32_t i = 0; i < cnt; ++i) {
            uintptr_t node = 0;
            std::uint32_t id = 0;
            if (!rdv(arr + 8ull * i, node) || !rdv(node + 0x38, id) || id == 0) { why = "node unreadable"; return false; }
            story[zone].push_back(id);
        }
    }
    if (story.empty()) { why = "no story entries"; return false; }
    return true;
}

void walk_now() {
    std::map<int, std::vector<std::uint32_t>> a, b;
    int za = 0, zb = 0;
    std::string why;
    if (!walk_zones(a, za, why)) { logw("[zones] walk skipped: %s", why.c_str()); return; }
    if (!walk_zones(b, zb, why) || a != b || za != zb) { logw("[zones] walk unstable; retrying later"); return; }
    if (g_ctx) g_ctx->progress.set_zone_table(a, za, "in-game zone table");
}

// --- local bot match --------------------------------------------------------
// The game's own debug option 0xa0 (G:0x9eb990 at ELF 0x8edd64..0x8edde8):
//   MP=0x4e2108(); 0x836ee0(MP,1); st=new(0x40); 0x837558(st); 0x82c0c8(g+0x398, st);
//   top=0x834528(g+0x398); top->vt[0x50](top, "ChangeState: MultiplayerStartLocalGame")
// -> state 0x837588 hosts a LAN match with this client as the authority (conn+0x6c=1).
// The 132 bytes of that sequence are compared first, which pins every callee address.
const char* kSeqHex =
    "e9d0ef97e10300325d24fd97cec9ef9713600e91e0031a3273c7e897f40300aaf525fd97e00313aae10314aacef8fc97c5c9ef97"
    "00600e91e319fd97f30300aaffff11a9e0630491ff9700f9ac6cec97b45e0090945e3191e00314aa628dec97e20300aae0630491"
    "e10314aa9ed6ec97680240f9e1630491e00313aa082940f900013fd6";

std::vector<unsigned char> unhex(const char* h) {
    std::vector<unsigned char> v;
    for (std::size_t i = 0; h[i] && h[i + 1]; i += 2) v.push_back(static_cast<unsigned char>(std::stoi(std::string(h + i, 2), nullptr, 16)));
    return v;
}

void start_bot_match_now(int bots) {
    using Fptr = void* (*)();
    void* mp = reinterpret_cast<Fptr>(g_base + 0x4e2108)();
    uintptr_t m = reinterpret_cast<uintptr_t>(mp), b338 = 0, b110 = 0;
    // 0x837588 dereferences *(MP+0xb338)+0x110 with no NULL check (ELF 0x83773c..0x837744).
    if (m < 0x1000 || !rdv(m + 0xb338, b338) || b338 < 0x1000 || !rdv(b338 + 0x110, b110) || b110 < 0x1000) {
        logw("[botmatch] NOT started: multiplayer data not ready (MP=0x%llx +0xb338=0x%llx +0x110=0x%llx). "
             "Open the Multiplayer menu once, then enter the code again.",
             static_cast<unsigned long long>(m), static_cast<unsigned long long>(b338),
             static_cast<unsigned long long>(b110));
        return;
    }
    reinterpret_cast<void (*)(void*, int)>(g_base + 0x836ee0)(mp, 1);
    void* g = reinterpret_cast<Fptr>(g_base + 0x4e04a8)();
    if (!g) { logw("[botmatch] NOT started: no game object"); return; }
    void* st = reinterpret_cast<void* (*)(std::size_t)>(g_base + 0x31fb48)(0x40);
    reinterpret_cast<void (*)(void*)>(g_base + 0x837558)(st);
    void* stk = static_cast<char*>(g) + 0x398;
    reinterpret_cast<void (*)(void*, void*)>(g_base + 0x82c0c8)(stk, st);
    void* top = reinterpret_cast<void* (*)(void*)>(g_base + 0x834528)(stk);
    if (top) {
        std::string s = "ChangeState: MultiplayerStartLocalGame";
        void** vt = *reinterpret_cast<void***>(top);
        reinterpret_cast<void (*)(void*, std::string*)>(vt[0x50 / 8])(top, &s);
    }
    g_bots_armed.store(bots);
    g_last_bm.store(0);
    logi("[botmatch] local match state pushed (MP=0x%llx, top=%p); %d bots will be requested when the match's "
         "bot manager appears", static_cast<unsigned long long>(m), top, bots);
}

// --- hooks --------------------------------------------------------------------
extern "C" void mc5_pump_hook(const char*, unsigned long long, unsigned long long, unsigned long long,
                              unsigned long long) {
    if (g_cheats_pending.exchange(false)) apply_cheats_now();
    if (g_walk_pending.load()) {
        bool due;
        { std::lock_guard<std::mutex> l(g_walk_mu); due = std::chrono::steady_clock::now() >= g_walk_at; }
        if (due && g_walk_pending.exchange(false)) walk_now();
    }
    int bots = g_botmatch_pending.exchange(0);
    if (bots > 0) {
        if (g_seq_ok) start_bot_match_now(bots);
        else logw("[botmatch] NOT started: the game's local-match sequence did not match this build");
    }
}

// Bot tick 0xb083a8(bm): calls UpdateBotPlayers 0xb41a80 only if bm+0x58 > 0,
// bm+0x5c > 0 or bm+0x60 >= 1, and nothing in the client sets them. bm+0x58 = N with
// bm+3 = 1 arms the type-0 bot fill (one per frame, timer-gated). bm+0x20 = bots data
// (bots.bin), dereferenced by 0xb41a80 / 0xc42270: must be non-NULL.
extern "C" void mc5_bot_tick_hook(const char*, unsigned long long x0, unsigned long long, unsigned long long,
                                  unsigned long long) {
    int n = g_bots_armed.load();
    if (n <= 0) return;
    uintptr_t bm = static_cast<uintptr_t>(x0), data = 0;
    if (bm < 0x1000 || g_last_bm.load() == bm) return;
    if (!rdv(bm + 0x20, data) || data < 0x1000) return; // bots data not loaded yet
    std::int32_t c58 = 0;
    unsigned char b3 = 0;
    rdv(bm + 0x58, c58);
    rdv(bm + 3, b3);
    *reinterpret_cast<volatile std::int32_t*>(bm + 0x58) = n;
    *reinterpret_cast<volatile unsigned char*>(bm + 3) = 1;
    g_last_bm.store(bm);
    logi("[bots] bot manager 0x%llx (data 0x%llx): bots %d -> %d, fill armed (bm+3 %d -> 1)",
         static_cast<unsigned long long>(bm), static_cast<unsigned long long>(data), c58, n, b3);
}

} // namespace

void set_context(ServerContext* ctx) { g_ctx = ctx; }

int install() {
    g_base = libmc5_base();
    if (!g_base) { logw("[gameplay] libMC5 not loaded"); return 0; }
    std::vector<unsigned char> seq = unhex(kSeqHex);
    g_seq_ok = bytes_match(0x8edd64, seq.data(), seq.size());
    g_settings_ok = bytes_match(kSettingsGetter, kSettingsGetterFp, sizeof(kSettingsGetterFp));
    g_camp_ok = bytes_match(kCampGetter, kCampGetterFp, sizeof(kCampGetterFp));
    static const unsigned char kPumpFp[16] = {0xff, 0x43, 0x01, 0xd1, 0xf4, 0x4f, 0x03, 0xa9,
                                              0xfd, 0x7b, 0x04, 0xa9, 0xfd, 0x03, 0x01, 0x91};
    static const unsigned char kBotTickFp[16] = {0xf3, 0x0f, 0x1e, 0xf8, 0xfd, 0x7b, 0x01, 0xa9,
                                                 0xfd, 0x43, 0x00, 0x91, 0x08, 0x58, 0x40, 0xb9};
    int n = install_entry_hook("GamePump(0x5f5128)", 0x5f5128, kPumpFp, reinterpret_cast<void*>(&mc5_pump_hook));
    n += install_entry_hook("BotTick(0xb083a8)", 0xb083a8, kBotTickFp, reinterpret_cast<void*>(&mc5_bot_tick_hook));
    logi("[gameplay] %d/2 hooks; local-match sequence %s, settings getter %s, campaign getter %s", n,
         g_seq_ok ? "ok" : "MISMATCH", g_settings_ok ? "ok" : "MISMATCH", g_camp_ok ? "ok" : "MISMATCH");
    return n;
}

void queue_cheats(bool god, bool ammo, bool medkits) {
    g_cheat_bits.store((god ? 1 : 0) | (ammo ? 2 : 0) | (medkits ? 4 : 0));
    g_cheats_pending.store(true);
}

void queue_zone_walk() {
    { std::lock_guard<std::mutex> l(g_walk_mu); g_walk_at = std::chrono::steady_clock::now() + std::chrono::seconds(2); }
    g_walk_pending.store(true);
}

std::string queue_bot_match(int bots) {
    if (!g_seq_ok) return "the game's local-match code did not match this build";
    if (bots < 1) bots = 1;
    if (bots > 12) bots = 12;
    g_botmatch_pending.store(bots);
    return std::string();
}

} // namespace gameplay
} // namespace mc5
