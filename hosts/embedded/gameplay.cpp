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
#include <cstdio>
#include <cstdlib>
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
std::atomic<bool> g_qp_enabled{true};
std::atomic<int> g_qp_search_min{3}, g_qp_search_max{8};
std::atomic<uintptr_t> g_last_bm{0};
void* g_pushed_st = nullptr;  // our MultiplayerStartLocalGame state (game thread only)
int g_pushed_frames = 0;
long g_dump_next_ms = 0;       // match-state diagnostic throttle (game thread only)
int g_dump_left = 0;
std::atomic<int> g_bottick_n{0}; // how many times the bot-manager tick fired (diagnostic)
bool g_realplay_ok = false;      // engine-spawn functions fingerprinted (ensure_playable)
bool g_spawn_done = false;       // local player engine-spawned this match (game thread only)
// Bots for the running local match: re-asserted on every bot tick (game thread).
std::atomic<int> g_bot_target{0};
std::atomic<bool> g_local_active{false}; // a local match we started is (being) hosted

// Quick Play -> local hosted match (game thread only; QPM::Update and the pump share it).
struct QuickPlay {
    bool active = false;      // parked search in progress
    bool fire = false;        // start the local match on the next pump
    uintptr_t qpm = 0;
    int mode = -1, cap = 0, map = -1;
    long deadline_ms = 0;
} g_qp;
// Parameters the 0xae3828 hook applies to the local-host settings (set when QP fires).
struct HostSettings { bool use = false; int mode = -1, cap = 0, map = -1; } g_hs;

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
        // The builder (G:0x9e1858) also makes entries for the special indices Z..n-1;
        // they are never consulted (cap Z-2), so skip them instead of rejecting.
        if (zone < 0 || zone >= n) { why = "entry zone " + std::to_string(zone) + " out of range"; return false; }
        if (zone >= Z) continue;
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
    g_local_active.store(true);
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
    g_bot_target.store(bots);
    g_last_bm.store(0);
    g_pushed_st = st;
    g_pushed_frames = 0;
    g_dump_left = 30; // dump match state once/second for the first 30 s (diagnostic)
    g_dump_next_ms = 0;
    g_spawn_done = false;
    logi("[botmatch] local match state pushed (MP=0x%llx, top=%p); %d bots will be requested when the match's "
         "bot manager appears", static_cast<unsigned long long>(m), top, bots);
}

// If host init fails (0xb365e8 false at 0x83785c), 0x837588 keeps its command vector and
// retries every frame: a frozen screen. After ~5 s with our state still on top and the
// command still pending, leave exactly the way the game's own "PopState" command does
// (0x8376dc..0x837718): destroy the strings (0x4226d0), empty the vector, MP->vt[0x10],
// pop the state stack (0x82c218, which deletes the state), then clear MP+0xc4.
void watch_local_match() {
    if (!g_pushed_st) return;
    void* g = reinterpret_cast<void* (*)()>(g_base + 0x4e04a8)();
    if (!g) { g_pushed_st = nullptr; return; }
    void* stk = static_cast<char*>(g) + 0x398;
    void* top = reinterpret_cast<void* (*)(void*)>(g_base + 0x834528)(stk);
    if (top != g_pushed_st) {
        logi("[botmatch] local match state left the stack after %d frames (match started or closed)", g_pushed_frames);
        g_pushed_st = nullptr;
        g_hs.use = false;
        return;
    }
    if (++g_pushed_frames < 300) return;
    uintptr_t st = reinterpret_cast<uintptr_t>(g_pushed_st), vb = 0, ve = 0;
    if (!rdv(st + 0x28, vb) || !rdv(st + 0x30, ve) || ve <= vb || (ve - vb) % 0x18 != 0) {
        g_pushed_st = nullptr;
        return;
    }
    logw("[botmatch] local match host init did not succeed after %d frames (UDP 7891 setup failed?); leaving the "
         "state the way the game's PopState does", g_pushed_frames);
    for (uintptr_t e = ve; e > vb;) { e -= 0x18; reinterpret_cast<void (*)(void*)>(g_base + 0x4226d0)(reinterpret_cast<void*>(e)); }
    *reinterpret_cast<uintptr_t*>(st + 0x30) = vb;
    void* mp = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
    if (mp) {
        void** vt = *reinterpret_cast<void***>(mp);
        reinterpret_cast<void (*)(void*)>(vt[0x10 / 8])(mp);
    }
    reinterpret_cast<void (*)(void*)>(g_base + 0x82c218)(stk);
    if (mp) reinterpret_cast<void (*)(void*, int)>(g_base + 0x836ee0)(mp, 0);
    g_pushed_st = nullptr;
    g_hs.use = false;
    g_bots_armed.store(0);
    g_bot_target.store(0);
    g_local_active.store(false);
}

// The hosted match registers the host's own player entry via MP->vt[0xc8] = 0xae3a70:
// SetLocalId(0), then AddPlayer 0xae3ad0 with state 4 -- and AddPlayer keeps the id
// only for state 1 (0xae3b20 cmp / 0xae3b30 csinv), so the entry gets id -1. Shipping
// clients were never the host, so this never mattered; for us the lookup 0xa62f58
// (id == local id) then fails and 0x799210 crashes at 0x799390. Give the host's entry
// (in use, slot 0, state 4, id -1) the local id. Entry = MP+0x1d0+k*0x28: +0 u16 in-use,
// +0x16 slot, +0x18 s16 id, +0x1b state, +0x20 info.
void repair_host_entry(const char* where) {
    void* mp = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
    uintptr_t m = reinterpret_cast<uintptr_t>(mp);
    std::int32_t lid = -1;
    if (m < 0x1000 || !rdv(m + 0x15d0, lid) || lid < 0 || lid > 0x7f) return;
    int candidate = -1;
    for (int k = 0; k < 128; ++k) {
        uintptr_t e = m + 0x1d0 + 0x28ull * k;
        unsigned char used = 0; // +0 in-use byte (+1 is a separate flag)
        std::int16_t id = 0;
        unsigned char slot = 0, st = 0;
        if (!rdv(e, used) || !rdv(e + 0x18, id)) return;
        if (id == lid) return; // already resolvable
        if (used == 1 && id == -1 && rdv(e + 0x16, slot) && rdv(e + 0x1b, st) && slot == 0 && st == 4 && candidate < 0)
            candidate = k;
    }
    if (candidate < 0) return;
    *reinterpret_cast<volatile std::int16_t*>(m + 0x1d0 + 0x28ull * candidate + 0x18) = static_cast<std::int16_t>(lid);
    logi("[botmatch] host player entry %d: id -1 -> %d (%s)", candidate, lid, where);
}

// --- peerless AI bots (fill a hosted match with bots that hold no connection) -------
// The hosted match's connection object has one peer slot, taken by the host, so the
// game's own AddBot (which needs a peer) can seat at most one bot. Instead we add each
// bot straight to the multiplayer manager's player table with a unique negative
// "connection slot" sentinel, mark the slot object a bot, and run the game's own
// BotReady 0xae5bf0 so it gets a team, a loadout and the ready state -- all dispatched
// locally, never over the wire. Five small filter hooks keep a negative slot from
// reaching code that would index a per-slot array or write an outgoing stream with it.
// See docs/research/06-zones-cheats-bots.md (B) and filter_tramp.hpp. Nothing here has
// run on a device yet: every address is fingerprinted at install() and every step bails
// safely on a surprise. All of it runs on the game thread (the bot tick).
std::atomic<bool> g_peerless{true}; // settings bots.peerless; false = legacy game fill
bool g_bots_ok = false;             // every called function fingerprinted at install()
bool g_sink_ok = false;             // the outgoing-stream ctor 0x8cff28 fingerprinted
uintptr_t g_inj_bm = 0;             // bot manager of the match we are filling (game thread)

// Two "bit bucket" outgoing streams returned for bot slots by H1/H2. The writers bound
// each write to the buffer and set an overflow flag; the buffer is reset each tick and
// is never flushed to a socket.
alignas(16) unsigned char g_sinkA[0x40];
alignas(16) unsigned char g_sinkB[0x40];
std::vector<unsigned char> g_sinkbufA, g_sinkbufB;

void init_sinks() {
    if (!g_sink_ok) return;
    if (g_sinkbufA.empty()) { g_sinkbufA.assign(0x10000, 0); g_sinkbufB.assign(0x10000, 0); }
    using Ctor = void (*)(void*, void*, int, int); // (stream, buf, size, mode)
    Ctor ctor = reinterpret_cast<Ctor>(g_base + 0x8cff28);
    ctor(g_sinkA, g_sinkbufA.data(), 0x10000, 0);
    ctor(g_sinkB, g_sinkbufB.data(), 0x10000, 0);
}

// Low 32 bits of a register argument, read as a signed slot (bot slots arrive
// sign-extended into w1, e.g. -2; a real slot is 0..0x7f).
inline int slot_arg(unsigned long long x) { return static_cast<int>(static_cast<std::uint32_t>(x)); }

// H1 0xb20518 / H2 0xb2a560: the authority's per-slot outgoing-stream getters. For a bot
// (negative slot) hand back a sink instead of letting them index out of range / return
// NULL (no caller null-checks the result).
extern "C" int mc5_h1_stream(unsigned long long, unsigned long long slot, unsigned long long,
                             unsigned long long, unsigned long long* ret) {
    if (slot_arg(slot) < 0) { *ret = reinterpret_cast<unsigned long long>(g_sinkA); return 1; }
    return 0;
}
extern "C" int mc5_h2_stream(unsigned long long, unsigned long long slot, unsigned long long,
                             unsigned long long, unsigned long long* ret) {
    if (slot_arg(slot) < 0) { *ret = reinterpret_cast<unsigned long long>(g_sinkB); return 1; }
    return 0;
}
// H3 0x8cc990: frees connection peer[slot]. Only slot 0 is a real peer; for any other
// slot (a bot's sentinel, or a stray) do nothing -- the real function indexes the peer
// array with no bound and would corrupt memory for slot != 0.
extern "C" int mc5_h3_peerfree(unsigned long long, unsigned long long slot, unsigned long long,
                               unsigned long long, unsigned long long* ret) {
    if (slot_arg(slot) != 0) { *ret = 0; return 1; }
    return 0;
}
// H5 0xb04800: writes MP[0xcc+slot]=1. Valid slots are 0..0x7f; a bot's negative slot
// would scribble over MP+0xbf..0xca (the host-state and clock-sync bytes). Run the
// original only for a real slot.
extern "C" int mc5_h5_hoststate(unsigned long long, unsigned long long slot, unsigned long long,
                                unsigned long long, unsigned long long* ret) {
    if (static_cast<std::uint32_t>(slot) < 0x80) return 0;
    *ret = 0;
    return 1;
}
// H4 0xaf9000: the msg-0xe5 forwarder, addressed by player id. If that id belongs to a
// bot (its table entry has a negative slot) drop the message rather than forward it
// through the by-slot stream.
extern "C" int mc5_h4_e5(unsigned long long mp, unsigned long long msg, unsigned long long,
                         unsigned long long, unsigned long long* ret) {
    std::int16_t id = 0;
    if (!rdv(msg + 0xa, id)) return 0;
    for (int k = 0; k < 128; ++k) {
        uintptr_t e = static_cast<uintptr_t>(mp) + 0x1d0 + 0x28ull * k;
        std::int16_t eid = 0;
        if (!rdv(e + 0x18, eid)) return 0;
        if (eid == id) {
            signed char slot = 0;
            if (rdv(e + 0x16, slot) && slot < 0) { *ret = 0; return 1; }
            return 0;
        }
    }
    return 0;
}

bool authority_ok(uintptr_t MP) {
    return (reinterpret_cast<int (*)(void*)>(g_base + 0xac02c0)(reinterpret_cast<void*>(MP)) & 1) != 0;
}

struct InjBot { int id; signed char slot; };
std::vector<InjBot> g_inj; // bots we injected into the live match (game thread only)

// Add one bot to the player table with the k-th negative sentinel slot. Every game call
// is by fingerprinted address; any surprise value bails without touching more state.
bool inject_one_bot(uintptr_t MP, int k) {
    void* gi = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
    if (reinterpret_cast<uintptr_t>(gi) != MP) return false;
    int id = reinterpret_cast<int (*)(void*)>(g_base + 0xae3dd8)(reinterpret_cast<void*>(MP)); // free id
    if (id < 1 || id > 0x7f) return false;
    int cap = 0;
    rdv(MP + 0x1880, cap);
    unsigned char lowpop = 0;
    if (rdv(MP + 0x1894, lowpop) && (lowpop & 1)) cap -= 4;
    if (cap < 2) cap = 2;
    if (cap > 12) cap = 12;
    if (id >= cap) return false;
    if (reinterpret_cast<int (*)(void*, int)>(g_base + 0xa62f10)(reinterpret_cast<void*>(MP), id)) return false; // in use

    static const char* kCallsigns[12] = {"Ghost", "Viper",  "Reaper", "Havoc", "Blaze",   "Talon",
                                         "Wraith", "Nomad", "Saint",  "Fury",  "Specter", "Raptor"};
    char uid[20] = {0};
    std::snprintf(uid, sizeof(uid), "%s", kCallsigns[k % 12]);
    char cred[32];
    int* ctr = reinterpret_cast<int*>(g_base + 0x1bc2d88);
    std::snprintf(cred, sizeof(cred), "bot_credentials_%d", (*ctr)++);

    // AddPlayer(MP, uid20, slot=0x7f (a temp >=0 slot, so it is accepted), id, botType=0,
    // cred, NULL, cred2, 0, state=1). state 1 is what makes the entry keep the id.
    using AddPlayer = void (*)(void*, const void*, int, int, int, const char*, void*, const char*, int, int);
    reinterpret_cast<AddPlayer>(g_base + 0xae3ad0)(reinterpret_cast<void*>(MP), uid, 0x7f, id, 0, cred, nullptr,
                                                   cred, 0, 1);
    void* ep = reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa62f58)(reinterpret_cast<void*>(MP), id);
    if (!ep) return false;
    uintptr_t e = reinterpret_cast<uintptr_t>(ep);
    unsigned char used = 0, st = 0;
    std::int16_t eid = 0;
    if (!rdv(e, used) || !rdv(e + 0x18, eid) || !rdv(e + 0x1b, st) || used != 1 || eid != id || st != 1)
        return false;
    signed char sent = static_cast<signed char>(-(2 + k)); // -2, -3, ...: never 0 (host) or -1 (free)
    *reinterpret_cast<volatile signed char*>(e + 0x16) = sent;

    void* so = reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa58a40)(reinterpret_cast<void*>(MP), id);
    if (!so) return false;
    reinterpret_cast<void (*)(void*, int)>(g_base + 0x65b8d0)(so, 1); // slot object +0x58 = isBot
    void** svt = *reinterpret_cast<void***>(so);
    reinterpret_cast<void (*)(void*, int)>(svt[0x40 / 8])(so, 0);     // bot kind 0 (base AI)
    reinterpret_cast<void (*)(void*, int)>(g_base + 0xae5bf0)(reinterpret_cast<void*>(MP), id); // BotReady
    reinterpret_cast<void (*)(void*)>(g_base + 0xaf3170)(reinterpret_cast<void*>(MP));          // enter CanStart map

    bool inuse = reinterpret_cast<int (*)(void*, int)>(g_base + 0xa661a0)(reinterpret_cast<void*>(MP), id) & 1;
    bool ready = reinterpret_cast<int (*)(void*, int)>(g_base + 0xa654f0)(reinterpret_cast<void*>(MP), id) & 1;
    g_inj.push_back({id, sent});
    logi("[bots] injected '%s' id %d slot %d inuse=%d ready=%d (%d/%d)", uid, id, sent, inuse, ready,
         static_cast<int>(g_inj.size()), g_bot_target.load());
    return true;
}

// Called from the bot tick while our hosted match is live: add one bot per tick up to
// the target, and keep the bot manager's counter equal to how many we have, so its own
// UpdateBotPlayers neither adds (its AddBot cannot seat a second peer) nor churns.
void drive_peerless_bots(uintptr_t bm, uintptr_t MP) {
    int target = g_bot_target.load();
    if (target <= 0 || !g_bots_ok) return;
    if (!authority_ok(MP)) return;
    if (g_inj_bm != bm) { g_inj_bm = bm; g_inj.clear(); } // new match
    repair_host_entry("bot tick");
    if (static_cast<int>(g_inj.size()) < target) {
        init_sinks();
        inject_one_bot(MP, static_cast<int>(g_inj.size()));
    }
    std::int32_t c58 = 0;
    rdv(bm + 0x58, c58);
    int have = static_cast<int>(g_inj.size());
    if (c58 != have) *reinterpret_cast<volatile std::int32_t*>(bm + 0x58) = have;
}

// Diagnostic: while our hosted match is live, dump the local player and each bot's
// state once per second for the first ~15 s, plus the match phase byte. This tells a
// device run whether the black screen is the local player (host) not spawning like a
// real participant, versus a phase/render issue. Logging only; all reads are guarded.
void dump_match_state(uintptr_t MP) {
    long now = static_cast<long>(reinterpret_cast<int (*)()>(g_base + 0x4e1c98)());
    if (g_dump_left <= 0 || now < g_dump_next_ms) return;
    g_dump_next_ms = now + 1000;
    --g_dump_left;
    std::int32_t lid = -1;
    unsigned char phase = 0;
    rdv(MP + 0x15d0, lid);
    rdv(MP + 0xc4, phase);
    // the local player's table entry (by id) and its slot object
    void* ep = lid >= 0 ? reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa62f58)(reinterpret_cast<void*>(MP), lid)
                        : nullptr;
    int st = -1, team = -1; signed char slot = 0;
    if (ep) {
        uintptr_t e = reinterpret_cast<uintptr_t>(ep);
        unsigned char b_st = 0, b_tm = 0; rdv(e + 0x1b, b_st); rdv(e + 0x1a, b_tm); rdv(e + 0x16, slot);
        st = b_st; team = b_tm;
    }
    void* so = lid >= 0 ? reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa58a40)(reinterpret_cast<void*>(MP), lid)
                        : nullptr;
    int ready = -1;
    if (so) { ready = reinterpret_cast<int (*)(void*, int)>(g_base + 0xa654f0)(reinterpret_cast<void*>(MP), lid) & 1; }
    int canstart = reinterpret_cast<int (*)(void*, int)>(g_base + 0xb083f8)(reinterpret_cast<void*>(MP), 0) & 1;
    uintptr_t bm = 0; std::int32_t bm58 = -1;
    if (rdv(MP + 0xb340, bm) && bm >= 0x1000) rdv(bm + 0x58, bm58);
    logi("[match] c4=%u canStart=%d localId=%d entry{state=%d team=%d slot=%d} soldier=%s ready=%d bots=%d bm58=%d ticks=%d",
         phase, canstart, lid, st, team, slot, so ? "yes" : "no", ready, static_cast<int>(g_inj.size()), bm58,
         g_bottick_n.load());
    for (const auto& b : g_inj) {
        void* bso = reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa58a40)(reinterpret_cast<void*>(MP), b.id);
        int br = reinterpret_cast<int (*)(void*, int)>(g_base + 0xa654f0)(reinterpret_cast<void*>(MP), b.id) & 1;
        int bt = -1;
        if (bso) { int t = reinterpret_cast<int (*)(void*)>(g_base + 0x5bb930)(bso); bt = t; }
        logi("[match]   bot id=%d slot=%d soldier=%s ready=%d team=%d", b.id, b.slot, bso ? "yes" : "no", br, bt);
    }
}

// Spawn the LOCAL player as a real soldier by running the game's own per-player spawn
// builder, exactly as it does for bots and remote players. The earlier EnsureComponents
// path baked state 0x147260 (lobby set: no loadout/view component) which is why the host's
// +0x4d0 stayed NULL; the engine's builder picks the in-match soldier state 0x14726d
// (local) which creates the loadout AND the first-person view/camera. (RE workflow
// wf_898606f8-2f8, binary-verified.)
//   ctx = 0x511a68() (controller singleton; the camera is stored at ctx+0x308)
//   gate = 0x5be670(MP): the builder chooses 0x14726d only while this is true (MP+0x1878==10);
//          it is true during the match, since our bots spawned through the same gate.
//   0x5be1c8(ctx, localId, localId+1): new entity -> applyComponentSet(0x14726d) -> bind
//          +0x4d0 -> team 1 (bridge-safe) -> register into MP+0x1f18 -> first-person camera.
//   The builder does not set readiness, so set slotobj+0x708=3 (0x4f5428) for the local
//   player and each bot, then 0xaf3170(MP) admits them to the CanStart map so the round
//   starts. Runs once per match. Game thread only.
void ensure_playable(uintptr_t MP) {
    if (g_spawn_done || !g_realplay_ok || !authority_ok(MP)) return;
    std::int32_t lid = -1;
    if (!rdv(MP + 0x15d0, lid) || lid < 0) return;
    // Wait until bots exist (the match is live) before spawning the local player.
    if (g_inj.empty()) return;
    void* ctx = reinterpret_cast<void* (*)()>(g_base + 0x511a68)();
    if (!ctx) return;
    // The builder 0x5be1c8 picks the in-match soldier state 0x14726d (loadout + camera) only
    // when its gate 0x5be670 is true, i.e. MP+0x1878 == 10. Our local-host match never sets
    // that phase, so force it to 10 just around the one call, then restore it (the field is
    // read only by the gate; we are on the game thread, so nothing else races it).
    std::int32_t saved_phase = 0;
    bool have_phase = rdv(MP + 0x1878, saved_phase);
    if (have_phase) *reinterpret_cast<volatile std::int32_t*>(MP + 0x1878) = 10;
    reinterpret_cast<void (*)(void*, int, int)>(g_base + 0x5be1c8)(ctx, lid, lid + 1); // engine local spawn
    if (have_phase) *reinterpret_cast<volatile std::int32_t*>(MP + 0x1878) = saved_phase;
    auto set_ready = [&](int id) {
        void* so = reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa58a40)(reinterpret_cast<void*>(MP), id);
        if (so) reinterpret_cast<void (*)(void*, int)>(g_base + 0x4f5428)(so, 3); // slotobj+0x708 = 3
    };
    set_ready(lid);
    for (const auto& b : g_inj) set_ready(b.id);
    reinterpret_cast<void (*)(void*)>(g_base + 0xaf3170)(reinterpret_cast<void*>(MP)); // admit to CanStart map
    g_spawn_done = true;
    void* so = reinterpret_cast<void* (*)(void*, int)>(g_base + 0xa58a40)(reinterpret_cast<void*>(MP), lid);
    uintptr_t wm = 0;
    if (so) rdv(reinterpret_cast<uintptr_t>(so) + 0x4d0, wm);
    logi("[match] local player engine-spawned (id=%d); +0x4d0=%s, %d bots readied", lid, wm ? "ok" : "null",
         static_cast<int>(g_inj.size()));
}

// Mission start 0x799210 (MP branch looks the local player up by id): repair first.
extern "C" void mc5_mission_start_hook(const char*, unsigned long long, unsigned long long, unsigned long long,
                                       unsigned long long) {
    if (g_local_active.load()) repair_host_entry("mission start");
}

// Settings copy 0xae3828(MP, settings) -- only the call from the local-host state
// (return address 0x8377b0 inside 0x837588) is touched: substitute the Quick Play mode
// record, map and capacity the player picked (the game's local host always used mode
// record 0 and its capacity). Records R = *(*(MP+0xb338)+0x110), 12 x 0x38 bytes:
// [0] = R[m]+0x14, [4] = map, [8] = capacity, [0xc] = R[m]+0x30 * 60000 ms,
// [0x10] = R[m]+0x2c -- exactly what the Quick Play builder 0xbf1da0 writes.
extern "C" void mc5_settings_hook(const char*, unsigned long long x0, unsigned long long x1, unsigned long long,
                                  unsigned long long lr) {
    if (!g_hs.use || lr != g_base + 0x8377b0) return; // cleared when our state leaves the stack
    uintptr_t mp = static_cast<uintptr_t>(x0), b338 = 0, recs = 0;
    if (mp < 0x1000 || !rdv(mp + 0xb338, b338) || !rdv(b338 + 0x110, recs) || recs < 0x1000) return;
    std::int32_t* st = reinterpret_cast<std::int32_t*>(x1);
    std::int32_t before[5];
    if (!rd(static_cast<uintptr_t>(x1), before, sizeof(before))) return;
    if (g_hs.mode >= 0 && g_hs.mode < 12) {
        std::int32_t gm = 0, t = 0, f2c = 0;
        uintptr_t r = recs + 0x38ull * g_hs.mode;
        if (rdv(r + 0x14, gm) && rdv(r + 0x30, t) && rdv(r + 0x2c, f2c)) {
            st[0] = gm;
            if (t > 0 && t < 120) st[3] = t * 60000;
            st[4] = f2c;
        }
    }
    // Map: Quick Play stores the map COUNT in QPM+0x52c0 as "server picks" (0xbf0ec0), so
    // only a hint that is a real index (0 <= hint < count, count from MapDB
    // *(*(base+0x1b9aee0)) vector +0x20/+0x28 stride 0x98, as 0x8dc850/0x8dc8b8) replaces
    // the local host's own choice (MapDB+0x3c, else rand()%4).
    {
        uintptr_t got = 0, db = 0, b = 0, e = 0;
        long count = -1;
        if (rdv(g_base + 0x1b9aee0, got) && rdv(got, db) && rdv(db + 0x20, b) && rdv(db + 0x28, e) && e >= b &&
            (e - b) % 0x98 == 0)
            count = static_cast<long>((e - b) / 0x98);
        if (g_hs.map >= 0 && g_hs.map < count) st[1] = g_hs.map;
    }
    if (g_hs.cap >= 2 && g_hs.cap <= 12) st[2] = g_hs.cap;
    logi("[quickplay] local host settings: mode %d->%d map %d->%d players %d->%d time %d->%d ms (QP mode id %d)",
         before[0], st[0], before[1], st[1], before[2], st[2], before[3], st[3], g_hs.mode);
}

// QPM::Update 0xbe6ce8 (game thread, every frame). The native Quick Play FSM is flow
// QPM+0x516c == 1 with its state in .bss 0x1bc4604; state 2 is "start searching" and
// would send automatch to Gameloft's matchmaker (dead). Instead: park the FSM on state 1
// (no case in the flow-1 switch) and keep its 60 s timeout clock QPM+0x5170 fresh, so the
// game's own SEARCHING screen stays up for a few seconds; then start a locally hosted
// match with the player's mode and capacity (QPM+0x52c4 / +0x52c8 / map hint +0x52c0).
constexpr uintptr_t kQpState = 0x1bc4604;
extern "C" void mc5_qp_update_hook(const char*, unsigned long long x0, unsigned long long, unsigned long long,
                                   unsigned long long) {
    try {
    uintptr_t qpm = static_cast<uintptr_t>(x0);
    if (qpm < 0x1000 || !g_seq_ok) return;
    std::int32_t flow = 0, state = 0;
    if (!rdv(qpm + 0x516c, flow) || !rdv(g_base + kQpState, state)) return;
    auto now_ms = [] { return static_cast<long>(reinterpret_cast<int (*)()>(g_base + 0x4e1c98)()); };
    if (!g_qp.active) {
        if (flow != 1 || state != 2 || g_pushed_st || !g_qp_enabled.load()) return;
        std::int32_t mode = -1, cap = 0, map = -1;
        rdv(qpm + 0x52c4, mode);
        rdv(qpm + 0x52c8, cap);
        rdv(qpm + 0x52c0, map);
        if (mode < 0 || mode >= 12 || mode == 8) {
            static std::int32_t warned_for = -1;
            std::int32_t t0 = 0;
            rdv(qpm + 0x5170, t0);
            if (warned_for != t0) {
                warned_for = t0;
                logw("[quickplay] mode id %d is not hosted offline (Battle Royale / unknown); leaving the native flow", mode);
            }
            return;
        }
        g_qp.active = true;
        g_qp.fire = false;
        g_qp.qpm = qpm;
        g_qp.mode = mode;
        g_qp.cap = cap < 2 ? 2 : (cap > 12 ? 12 : cap);
        g_qp.map = map;
        int lo = g_qp_search_min.load(), hi = g_qp_search_max.load();
        if (hi < lo) hi = lo;
        g_qp.deadline_ms = now_ms() + 1000L * (lo + static_cast<int>(static_cast<unsigned>(rand()) % (hi - lo + 1)));
        logi("[quickplay] Quick Play mode id %d, %d players (map hint %d): searching locally, then hosting with %d bots",
             mode, g_qp.cap, map, g_qp.cap - 1);
    }
    if (flow != 1) {
        logi("[quickplay] search cancelled by the player");
        g_qp.active = false;
        return;
    }
    *reinterpret_cast<volatile std::int32_t*>(g_base + kQpState) = 1;          // parked
    *reinterpret_cast<volatile std::int32_t*>(qpm + 0x5170) = static_cast<std::int32_t>(now_ms()); // no 'qpte'
    if (!g_qp.fire && now_ms() >= g_qp.deadline_ms) g_qp.fire = true;
    } catch (...) {
        logw("[gameplay] exception in the Quick Play hook (ignored)");
    }
}

// --- hooks --------------------------------------------------------------------
extern "C" void mc5_pump_hook(const char*, unsigned long long, unsigned long long, unsigned long long,
                              unsigned long long) {
    try {
    watch_local_match();
    if (g_local_active.load() && !g_pushed_st) {
        void* mp = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
        unsigned char c4 = 0;
        if (mp && rdv(reinterpret_cast<uintptr_t>(mp) + 0xc4, c4) && c4 == 0) {
            logi("[botmatch] local match over (MP+0xc4 cleared)");
            g_local_active.store(false);
            g_bot_target.store(0);
        }
    }
    if (g_local_active.load()) {
        repair_host_entry("frame");
        void* mp = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
        if (mp) {
            try { ensure_playable(reinterpret_cast<uintptr_t>(mp)); }
            catch (...) { logw("[match] exception building loadouts (ignored)"); }
            dump_match_state(reinterpret_cast<uintptr_t>(mp));
        }
    }
    if (g_qp.active && g_qp.fire) {
        g_qp.active = false;
        g_qp.fire = false;
        std::int32_t flow = 0, state = 0;
        if (!rdv(g_qp.qpm + 0x516c, flow) || !rdv(g_base + kQpState, state) || flow != 1 || state != 1) {
            logi("[quickplay] search was cancelled; not hosting");
        } else if (g_pushed_st) {
            logw("[quickplay] a local match is already starting");
        } else {
            g_hs = HostSettings{true, g_qp.mode, g_qp.cap, g_qp.map};
            start_bot_match_now(g_qp.cap - 1);
            if (g_pushed_st) {
                // Release the native Quick Play flow: clear flow 1 (0xbf08a8) and its state.
                reinterpret_cast<void (*)(void*, int)>(g_base + 0xbf08a8)(reinterpret_cast<void*>(g_qp.qpm), 1);
                *reinterpret_cast<volatile std::int32_t*>(g_base + kQpState) = 0;
            } else {
                // Refused (logged): leave the native flow parked; its own 60 s timeout ends it.
                g_hs.use = false;
            }
        }
    }
    if (g_cheats_pending.exchange(false)) apply_cheats_now();
    if (g_walk_pending.load()) {
        bool due;
        { std::lock_guard<std::mutex> l(g_walk_mu); due = std::chrono::steady_clock::now() >= g_walk_at; }
        if (due && g_walk_pending.exchange(false)) walk_now();
    }
    int bots = g_botmatch_pending.exchange(0);
    if (bots > 0) {
        if (g_pushed_st) logw("[botmatch] NOT started: a local match is already starting");
        else if (g_seq_ok) start_bot_match_now(bots);
        else logw("[botmatch] NOT started: the game's local-match sequence did not match this build");
    }
    } catch (...) {
        logw("[gameplay] exception in the pump hook (ignored)");
    }
}

// Bot tick 0xb083a8(bm): calls UpdateBotPlayers 0xb41a80 only if bm+0x58 > 0,
// bm+0x5c > 0 or bm+0x60 >= 1, and nothing in the client sets them. bm+0x58 = N with
// bm+3 = 1 arms the type-0 bot fill (one per frame, timer-gated). bm+0x20 = bots data
// (bots.bin), dereferenced by 0xb41a80 / 0xc42270: must be non-NULL.
extern "C" void mc5_bot_tick_hook(const char*, unsigned long long x0, unsigned long long, unsigned long long,
                                  unsigned long long) {
    g_bottick_n.fetch_add(1);
    int n = g_bot_target.load();
    if (n <= 0) return;
    uintptr_t bm = static_cast<uintptr_t>(x0);
    if (bm < 0x1000) return;
    // Preferred path: inject bots that hold no connection, so a full lobby is possible.
    if (g_peerless.load() && g_bots_ok) {
        void* mp = reinterpret_cast<void* (*)()>(g_base + 0x4e2108)();
        uintptr_t MP = reinterpret_cast<uintptr_t>(mp), cur = 0;
        if (MP >= 0x1000 && rdv(MP + 0xb340, cur) && cur == bm) {
            try { drive_peerless_bots(bm, MP); } catch (...) { logw("[bots] exception in the bot tick (ignored)"); }
        }
        return;
    }
    // Legacy fill (the game's own AddBot; seats at most one bot on a hosted match).
    uintptr_t data = 0;
    if (!rdv(bm + 0x20, data) || data < 0x1000) return; // bots data not loaded yet
    // The local player must hold its id first, or the free-id search 0xae3dd8 (which skips
    // negative ids) would hand id 0 -- the local player's -- to the first bot.
    repair_host_entry("bot tick");
    std::int32_t c58 = 0;
    rdv(bm + 0x58, c58);
    if (c58 != n) {
        *reinterpret_cast<volatile std::int32_t*>(bm + 0x58) = n;
        *reinterpret_cast<volatile unsigned char*>(bm + 3) = 1;
        *reinterpret_cast<volatile std::int32_t*>(bm + 0x60) = 0;
        if (g_last_bm.exchange(bm) != bm || c58 != 0)
            logi("[bots] bot manager 0x%llx (data 0x%llx): bot target %d -> %d, type-0 fill armed",
                 static_cast<unsigned long long>(bm), static_cast<unsigned long long>(data), c58, n);
    }
}

} // namespace

void set_context(ServerContext* ctx) { g_ctx = ctx; }

void configure_quick_play(bool enabled, int search_min_s, int search_max_s) {
    g_qp_enabled.store(enabled);
    g_qp_search_min.store(search_min_s < 0 ? 0 : (search_min_s > 60 ? 60 : search_min_s));
    g_qp_search_max.store(search_max_s < 0 ? 0 : (search_max_s > 60 ? 60 : search_max_s));
}

void configure_bots(bool peerless) { g_peerless.store(peerless); }

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
    static const unsigned char kQpUpdFp[16] = {0xf3, 0x0f, 0x1e, 0xf8, 0xfd, 0x7b, 0x01, 0xa9,
                                               0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa};
    static const unsigned char kSettingsFp[16] = {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9,
                                                  0xfd, 0x43, 0x00, 0x91, 0x28, 0x58, 0x40, 0x39};
    static const unsigned char kMissionFp[16] = {0xff, 0x03, 0x01, 0xd1, 0xf6, 0x57, 0x01, 0xa9,
                                                 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9};
    n += install_entry_hook("QuickPlayUpdate(0xbe6ce8)", 0xbe6ce8, kQpUpdFp, reinterpret_cast<void*>(&mc5_qp_update_hook));
    n += install_entry_hook("MatchSettings(0xae3828)", 0xae3828, kSettingsFp, reinterpret_cast<void*>(&mc5_settings_hook));
    n += install_entry_hook("MissionStart(0x799210)", 0x799210, kMissionFp, reinterpret_cast<void*>(&mc5_mission_start_hook));
    logi("[gameplay] %d/5 hooks; local-match sequence %s, settings getter %s, campaign getter %s", n,
         g_seq_ok ? "ok" : "MISMATCH", g_settings_ok ? "ok" : "MISMATCH", g_camp_ok ? "ok" : "MISMATCH");

    // Peerless bots: verify every game function the injector calls, then install the
    // filter hooks that make a bot's negative slot harmless. If anything is off for this
    // build, g_bots_ok stays false and the bot tick falls back to the legacy fill.
    struct FnFp { uintptr_t a; unsigned char fp[16]; };
    static const FnFp kBotFns[] = {
        {0x8cff28, {0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
        {0xae3dd8, {0xff, 0x03, 0x01, 0xd1, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9, 0xfd, 0xc3, 0x00, 0x91}},
        {0xae3ad0, {0xf7, 0x0f, 0x1c, 0xf8, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},
        {0xa62f58, {0xe8, 0x03, 0x1f, 0xaa, 0x00, 0x40, 0x07, 0x91, 0x09, 0x30, 0xc0, 0x79, 0x3f, 0x01, 0x01, 0x6b}},
        {0xa62f10, {0x3f, 0x04, 0x00, 0x31, 0x80, 0x01, 0x00, 0x54, 0xe8, 0x03, 0x1f, 0xaa, 0x09, 0xa0, 0x07, 0x91}},
        {0xa58a40, {0xf5, 0x0f, 0x1d, 0xf8, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
        {0x65b8d0, {0x28, 0x00, 0x00, 0x12, 0x08, 0x60, 0x01, 0x39, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00, 0x00, 0x00}},
        {0xae5bf0, {0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9}},
        {0xaf3170, {0xf5, 0x0f, 0x1d, 0xf8, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
        {0xaf1030, {0xff, 0x83, 0x02, 0xd1, 0xfc, 0x6f, 0x04, 0xa9, 0xfa, 0x67, 0x05, 0xa9, 0xf8, 0x5f, 0x06, 0xa9}},
        {0xaf1748, {0xff, 0x43, 0x01, 0xd1, 0xf5, 0x13, 0x00, 0xf9, 0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b, 0x04, 0xa9}},
        {0xa661a0, {0xe9, 0x03, 0x1f, 0xaa, 0x08, 0x44, 0x07, 0x91, 0x0a, 0x71, 0xc1, 0x78, 0x5f, 0x01, 0x01, 0x6b}},
        {0xa654f0, {0xf3, 0x0f, 0x1e, 0xf8, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x01, 0x2a}},
        {0xac02c0, {0x08, 0x08, 0x40, 0xf9, 0xa8, 0x00, 0x00, 0xb4, 0x08, 0xb1, 0x41, 0x39, 0x1f, 0x01, 0x00, 0x71}},
        {0x4e2108, {0xc8, 0xb5, 0x00, 0x90, 0x08, 0xed, 0x46, 0xf9, 0x00, 0x01, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6}},
    };
    bool fns_ok = true;
    for (const auto& f : kBotFns)
        if (!bytes_match(f.a, f.fp, sizeof(f.fp))) {
            fns_ok = false;
            logw("[bots] function 0x%llx fingerprint mismatch", static_cast<unsigned long long>(f.a));
        }
    g_sink_ok = bytes_match(0x8cff28, kBotFns[0].fp, 16);
    int fh = 0;
    if (fns_ok) {
        static const unsigned char fpH1[16] = {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9,
                                               0xfd, 0x43, 0x00, 0x91, 0xf4, 0x03, 0x01, 0x2a};
        static const unsigned char fpH2[16] = {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9,
                                               0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x01, 0x2a};
        static const unsigned char fpH3[16] = {0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9,
                                               0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91};
        static const unsigned char fpH5[16] = {0x08, 0xc0, 0x21, 0x8b, 0xe9, 0x03, 0x00, 0x32,
                                               0x09, 0x31, 0x03, 0x39, 0xc0, 0x03, 0x5f, 0xd6};
        static const unsigned char fpH4[16] = {0xf5, 0x0f, 0x1d, 0xf8, 0xf4, 0x4f, 0x01, 0xa9,
                                               0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91};
        fh += install_filter_hook("H1 stream 0xb20518", 0xb20518, fpH1, reinterpret_cast<void*>(&mc5_h1_stream));
        fh += install_filter_hook("H2 stream 0xb2a560", 0xb2a560, fpH2, reinterpret_cast<void*>(&mc5_h2_stream));
        fh += install_filter_hook("H3 peerfree 0x8cc990", 0x8cc990, fpH3, reinterpret_cast<void*>(&mc5_h3_peerfree));
        fh += install_filter_hook("H5 hoststate 0xb04800", 0xb04800, fpH5, reinterpret_cast<void*>(&mc5_h5_hoststate));
        fh += install_filter_hook("H4 e5fwd 0xaf9000", 0xaf9000, fpH4, reinterpret_cast<void*>(&mc5_h4_e5));
    }
    g_bots_ok = fns_ok && g_sink_ok && fh >= 4; // H1,H2,H3,H5 required; H4 optional
    logi("[bots] peerless support: functions %s, %d/5 filter hooks -> %s", fns_ok ? "ok" : "MISMATCH", fh,
         g_bots_ok ? "ready" : "disabled (legacy fill)");

    // Real local play (ensure_playable): fingerprint the engine-spawn functions it calls; a
    // mismatch only disables the local-player spawn, not the bot path.
    struct FnFp2 { uintptr_t a; unsigned char fp[16]; };
    static const FnFp2 kSpawnFns[] = {
        {0x5be1c8, {0xff, 0x83, 0x01, 0xd1, 0xf7, 0x13, 0x00, 0xf9, 0xf6, 0x57, 0x03, 0xa9, 0xf4, 0x4f, 0x04, 0xa9}},
        {0x511a68, {0x48, 0xb4, 0x00, 0xd0, 0x08, 0x69, 0x40, 0xf9, 0x00, 0x01, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6}},
        {0x5be670, {0xf3, 0x0f, 0x1e, 0xf8, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa}},
        {0x4f5428, {0x01, 0x08, 0x07, 0xb9, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x08, 0x45, 0xb9, 0xc0, 0x03, 0x5f, 0xd6}},
        {0xaf3170, {0xf5, 0x0f, 0x1d, 0xf8, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
    };
    g_realplay_ok = true;
    for (const auto& f : kSpawnFns)
        if (!bytes_match(f.a, f.fp, sizeof(f.fp))) {
            g_realplay_ok = false;
            logw("[match] spawn function 0x%llx fingerprint mismatch", static_cast<unsigned long long>(f.a));
        }
    logi("[match] real local play %s", g_realplay_ok ? "ready" : "disabled");
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
    if (bots > 11) bots = 11; // 12 players with the host
    g_botmatch_pending.store(bots);
    return std::string();
}

} // namespace gameplay
} // namespace mc5
