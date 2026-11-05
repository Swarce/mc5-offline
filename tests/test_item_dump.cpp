// Unit test for hosts/embedded/item_dump.cpp over a synthetic memory image laid out
// like the libMC5 6.0.12a armory (docs/research/04-progression.md §10).
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "../hosts/embedded/item_dump.hpp"
#include "check.hpp"

using mc5::itemdump::fnv1a;

namespace {

// A sparse little-endian memory image with a bump allocator.
struct Mem {
    std::map<std::uint64_t, unsigned char> b;
    std::uint64_t next = 0x10000000;
    std::uint64_t alloc(std::size_t n) { std::uint64_t a = next; next += (n + 15) & ~15ull; for (std::size_t i = 0; i < n; ++i) b[a + i] = 0; return a; }
    void put(std::uint64_t a, const void* p, std::size_t n) { auto* c = static_cast<const unsigned char*>(p); for (std::size_t i = 0; i < n; ++i) b[a + i] = c[i]; }
    template <class T> void w(std::uint64_t a, T v) { put(a, &v, sizeof(T)); }
    bool read(std::uint64_t a, void* out, std::size_t n) const {
        auto* o = static_cast<unsigned char*>(out);
        for (std::size_t i = 0; i < n; ++i) { auto it = b.find(a + i); if (it == b.end()) return false; o[i] = it->second; }
        return true;
    }
    // libc++ std::string at `at` (short form <= 22 chars, else long form).
    void str(std::uint64_t at, const std::string& s) {
        unsigned char raw[24] = {0};
        if (s.size() <= 22) { raw[0] = static_cast<unsigned char>(s.size() << 1); std::memcpy(raw + 1, s.data(), s.size()); }
        else {
            std::uint64_t p = alloc(s.size() + 1);
            put(p, s.data(), s.size());
            std::uint64_t cap = ((s.size() + 16) & ~15ull) | 1, size = s.size();
            std::memcpy(raw, &cap, 8); std::memcpy(raw + 8, &size, 8); std::memcpy(raw + 16, &p, 8);
        }
        put(at, raw, 24);
    }
    // std::vector {begin,end,cap} at `at` over a fresh array of n*stride bytes.
    std::uint64_t vec(std::uint64_t at, std::size_t n, std::size_t stride) {
        std::uint64_t a = n ? alloc(n * stride) : 0;
        w<std::uint64_t>(at, a); w<std::uint64_t>(at + 8, a + n * stride); w<std::uint64_t>(at + 16, a + n * stride);
        return a;
    }
    std::uint64_t names(std::uint64_t at, const std::vector<std::string>& v) {
        std::uint64_t a = vec(at, v.size(), 0x18);
        for (std::size_t i = 0; i < v.size(); ++i) str(a + i * 0x18, v[i]);
        return a;
    }
};

} // namespace

int main() {
    Mem m;
    const std::uint64_t A = m.alloc(0x3a0);
    // Weapons: 2 base + 1 PRO variant.
    std::vector<std::string> w = {"m4a1", "a_weapon_with_a_long_name_x", "m4a1_PRO"};
    m.w<std::int32_t>(A + 0xc8, 2);
    m.names(A + 0x190, w);
    std::uint64_t wh = m.vec(A + 0xd0, 3, 4);
    for (int i = 0; i < 3; ++i) m.w<std::uint32_t>(wh + 4 * i, fnv1a(w[i]));
    m.vec(A + 0xe8, 3, 0x118);
    // Attachments: 3; WM rows for both base weapons.
    std::vector<std::string> at = {"scope", "silencer", "grip"};
    m.vec(A + 0x118, 3, 0x78);
    m.names(A + 0x1a8, at);
    std::uint64_t ah = m.vec(A + 0x100, 3, 4);
    for (int i = 0; i < 3; ++i) m.w<std::uint32_t>(ah + 4 * i, fnv1a(at[i]));
    std::uint64_t rows = m.vec(A + 0x160, 2, 0x18);
    {   // weapon 0: scope (v1=5), silencer default (v1=-1), scope again (ignored), grip (v1=2)
        std::uint64_t t = m.vec(rows, 4, 0xc);
        std::int32_t tr[4][3] = {{0, 5, 0}, {1, -1, 0}, {0, 9, 0}, {2, 2, 0}};
        for (int k = 0; k < 4; ++k) m.put(t + 0xc * k, tr[k], 0xc);
        std::uint64_t t1 = m.vec(rows + 0x18, 1, 0xc); // weapon 1: silencer v1=3
        std::int32_t tr1[3] = {1, 3, 0};
        m.put(t1, tr1, 0xc);
    }
    // Camos: one free (bit0), one locked.
    std::vector<std::string> cm = {"camo_free", "camo_gold"};
    std::uint64_t cr = m.vec(A + 0x288, 2, 0x70);
    m.names(A + 0x2a0, cm);
    for (int i = 0; i < 2; ++i) { m.w<std::uint32_t>(cr + 0x70 * i, fnv1a(cm[i])); m.w<std::uint32_t>(cr + 0x70 * i + 0x4c, i == 0 ? 1 : 0); }
    // Masks: one. Trinkets: one free, one not.
    std::uint64_t mr = m.vec(A + 0x258, 1, 0x90);
    m.names(A + 0x270, {"mask_skull"});
    m.w<std::uint32_t>(mr, fnv1a("mask_skull"));
    std::vector<std::string> tk = {"tk_free", "tk_dice"};
    std::uint64_t tr = m.vec(A + 0x2f8, 2, 0x40);
    m.names(A + 0x310, tk);
    for (int i = 0; i < 2; ++i) { m.w<std::uint32_t>(tr + 0x40 * i, fnv1a(tk[i])); m.w<std::uint32_t>(tr + 0x40 * i + 0x2c, i == 0 ? 1 : 0); }
    // Body pieces: one default (+0x39), one hidden (+0x40), one grantable. Body camos: one.
    std::vector<std::string> bp = {"assault_arms_A", "secret_legs", "heavy_torso_B"};
    std::uint64_t br = m.vec(A + 0x18, 3, 0x90);
    for (int i = 0; i < 3; ++i) {
        m.str(br + 0x90 * i + 0x10, bp[i]);
        m.w<std::uint32_t>(br + 0x90 * i + 8, fnv1a(bp[i]));
        m.w<unsigned char>(br + 0x90 * i + 0x39, i == 0);
        m.w<unsigned char>(br + 0x90 * i + 0x40, i == 1 ? 2 : 0);
    }
    std::uint64_t bc = m.vec(A + 0x0, 1, 0x98);
    m.str(bc + 0x10, "bodycamo_desert");
    m.w<std::uint32_t>(bc + 8, fnv1a("bodycamo_desert"));
    // Killsigs: one free ("none"), one with a condition.
    const std::uint64_t M = m.alloc(0x200);
    std::uint64_t ka = m.alloc(2 * 0x50);
    m.w<std::int32_t>(M + 0x1a8, 2);
    m.w<std::uint64_t>(M + 0x1b0, ka);
    const char* kn[2] = {"ks_basic", "ks_headshot"};
    for (int i = 0; i < 2; ++i) {
        m.str(ka + 0x50 * i, kn[i]);
        m.w<std::uint32_t>(ka + 0x50 * i + 0x18, fnv1a(kn[i]));
        m.w<std::uint32_t>(ka + 0x50 * i + 0x20, i == 0 ? fnv1a("none") : fnv1a("unlock_killsig_levelup"));
    }

    // Skills manager: 3 classes, one free (unlockLevel 1).
    const std::uint64_t S = m.alloc(0x40);
    std::uint64_t sb = m.vec(S + 0x10, 3, 0x78);
    const char* cn[3] = {"assault", "heavy", "recon"};
    for (int i = 0; i < 3; ++i) {
        m.w<std::uint32_t>(sb + 0x78 * i, fnv1a(cn[i]));
        m.str(sb + 0x78 * i + 8, cn[i]);
        m.w<std::int32_t>(sb + 0x78 * i + 0x28, i == 0 ? 1 : 5);
    }

    mc5::itemdump::ReadFn rd = [&m](std::uint64_t a, void* o, std::size_t n) { return m.read(a, o, n); };
    mc5::itemdump::Result r = mc5::itemdump::dump(rd, A, M, S);
    CHECK((r.groups["classes"] == std::vector<std::string>{"heavy", "recon"}));
    CHECK((r.groups["weapons"] == std::vector<std::string>{"m4a1", "a_weapon_with_a_long_name_x"}));
    CHECK((r.groups["attachments"] == std::vector<std::string>{"m4a1#scope", "m4a1#grip", "a_weapon_with_a_long_name_x#silencer"}));
    CHECK((r.groups["camos"] == std::vector<std::string>{"camo_gold"}));
    CHECK((r.groups["gear"] == std::vector<std::string>{"mask_skull", "tk_dice", "heavy_torso_B", "bodycamo_desert"}));
    CHECK((r.groups["killsigs"] == std::vector<std::string>{"ks_headshot"}));

    // A corrupted hash drops exactly that list.
    m.w<std::uint32_t>(cr + 0x70, 0xdeadbeef);
    mc5::itemdump::Result r2 = mc5::itemdump::dump(rd, A, M);
    CHECK(r2.groups.count("camos") == 0);
    CHECK(r2.groups.count("weapons") == 1);
    // An unreadable/absent armory yields nothing and does not crash.
    CHECK(mc5::itemdump::dump(rd, 0, 0).groups.empty());
    CHECK(mc5::itemdump::dump(rd, 0x5000, 0).groups.empty());
    // A bogus vector (end < begin) fails the weapons layout check.
    m.w<std::uint64_t>(A + 0x198, 1);
    CHECK(mc5::itemdump::dump(rd, A, 0).groups.count("weapons") == 0);
    return mc5test::failures();
}
