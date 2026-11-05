// item_dump.cpp — see item_dump.hpp. Offsets: docs/research/04-progression.md §10.
#include "item_dump.hpp"

#include <cstring>
#include <set>

namespace mc5 {
namespace itemdump {

std::uint32_t fnv1a(const std::string& s) {
    std::uint32_t h = 0x811c9dc5u;
    for (char c : s) {
        h ^= static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<signed char>(c)));
        h *= 0x01000193u;
    }
    return h;
}

namespace {

constexpr std::size_t kMaxElems = 4096;

struct Reader {
    const ReadFn& rd;
    template <class T> bool get(std::uint64_t a, T& v) const { return a >= 0x1000 && rd(a, &v, sizeof(T)); }
    bool bytes(std::uint64_t a, std::size_t n, std::vector<unsigned char>& out) const {
        out.assign(n, 0);
        return n == 0 || (a >= 0x1000 && rd(a, out.data(), n));
    }
    // A libc++ std::vector at `at`: element count with stride; false on any oddity.
    bool vec(std::uint64_t at, std::size_t stride, std::uint64_t& begin, std::size_t& n) const {
        std::uint64_t b = 0, e = 0, c = 0;
        if (!get(at, b) || !get(at + 8, e) || !get(at + 16, c)) return false;
        if (b == 0 && e == 0) { begin = 0; n = 0; return true; }
        if (b == 0 || e < b || c < e || (e - b) % stride != 0) return false;
        n = static_cast<std::size_t>((e - b) / stride);
        if (n > kMaxElems) return false;
        begin = b;
        return true;
    }
    // A libc++ std::string (0x18 bytes) at `at`. Printable ASCII, 1..127 chars.
    bool str(std::uint64_t at, std::string& out) const {
        unsigned char raw[24];
        if (at < 0x1000 || !rd(at, raw, sizeof(raw))) return false;
        out.clear();
        if ((raw[0] & 1) == 0) {
            std::size_t len = raw[0] >> 1;
            if (len == 0 || len > 22) return false;
            out.assign(reinterpret_cast<const char*>(raw + 1), len);
        } else {
            std::uint64_t cap, size, ptr;
            std::memcpy(&cap, raw, 8);
            std::memcpy(&size, raw + 8, 8);
            std::memcpy(&ptr, raw + 16, 8);
            if (size == 0 || size > 127 || size >= (cap & ~1ull) + 1 || ptr < 0x1000) return false;
            std::vector<unsigned char> b;
            if (!bytes(ptr, static_cast<std::size_t>(size), b)) return false;
            out.assign(b.begin(), b.end());
        }
        for (char ch : out)
            if (ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\') return false;
        return true;
    }
    bool names(std::uint64_t at, std::size_t expect, std::vector<std::string>& out) const {
        std::uint64_t b;
        std::size_t n;
        if (!vec(at, 0x18, b, n) || n != expect) return false;
        out.resize(n);
        for (std::size_t i = 0; i < n; ++i)
            if (!str(b + i * 0x18, out[i])) return false;
        return true;
    }
};

std::string note(const char* what, const std::string& msg) { return std::string(what) + ": " + msg; }

} // namespace

Result dump(const ReadFn& rd, std::uint64_t A, std::uint64_t M) {
    Result res;
    Reader r{rd};
    if (A < 0x1000) { res.notes.push_back("armory: not allocated"); return res; }

    // --- weapons: base weapons are indices 0..nW-1 (A+0xc8); names A+0x190, hashes
    // A+0xd0, records A+0xe8 (stride 0x118) are parallel (the WPP "_PRO" variants follow).
    std::vector<std::string> wnames;
    int nW = 0;
    {
        std::uint64_t hb, rb;
        std::size_t nh, nr;
        std::vector<std::string> all;
        std::uint64_t nb;
        std::size_t nn;
        if (!r.get(A + 0xc8, nW) || nW <= 0 || nW > 1024 || !r.vec(A + 0x190, 0x18, nb, nn) ||
            static_cast<std::size_t>(nW) > nn || !r.vec(A + 0xd0, 4, hb, nh) || nh != nn ||
            !r.vec(A + 0xe8, 0x118, rb, nr) || nr != nn || !r.names(A + 0x190, nn, all)) {
            res.notes.push_back("weapons: layout check failed");
            nW = 0;
        } else {
            bool ok = true;
            for (int i = 0; i < nW && ok; ++i) {
                std::uint32_t h;
                ok = r.get(hb + 4ull * i, h) && h == fnv1a(all[i]);
            }
            if (!ok) { res.notes.push_back("weapons: hash self-check failed"); nW = 0; }
            else {
                wnames.assign(all.begin(), all.begin() + nW);
                res.groups["weapons"] = wnames;
                res.notes.push_back(note("weapons", std::to_string(nW) + " base (+" + std::to_string(nn - nW) + " PRO variants not granted)"));
            }
        }
    }

    // --- attachments: records A+0x118 (0x78), names A+0x1a8, hashes A+0x100; the WM
    // compatibility rows A+0x160 (0x18 each) hold {u32 att, i32 v1, i32 v2} triples per
    // weapon. The game catalogs "<w>#<a>" when v1 > 0 (0x60f640 via 0x7eaa68, first
    // triple per att); v1 <= 0 is a default/free attachment, owned anyway.
    if (nW > 0) {
        std::uint64_t rb, hb, wb;
        std::size_t nA, nh, nrows;
        std::vector<std::string> an;
        if (!r.vec(A + 0x118, 0x78, rb, nA) || !r.vec(A + 0x100, 4, hb, nh) || nh != nA ||
            !r.names(A + 0x1a8, nA, an) || !r.vec(A + 0x160, 0x18, wb, nrows)) {
            res.notes.push_back("attachments: layout check failed");
        } else {
            bool ok = true;
            for (std::size_t i = 0; i < nA && ok; ++i) {
                std::uint32_t h;
                ok = r.get(hb + 4 * i, h) && h == fnv1a(an[i]);
            }
            std::vector<std::string> pairs;
            for (int w = 0; ok && w < nW && static_cast<std::size_t>(w) < nrows; ++w) {
                std::uint64_t tb;
                std::size_t nt;
                if (!r.vec(wb + 0x18ull * w, 0xc, tb, nt) || nt > 256) { ok = false; break; }
                std::vector<unsigned char> t;
                if (!r.bytes(tb, nt * 0xc, t)) { ok = false; break; }
                std::set<std::uint32_t> seen;
                for (std::size_t k = 0; k < nt; ++k) {
                    std::uint32_t att;
                    std::int32_t v1;
                    std::memcpy(&att, &t[k * 0xc], 4);
                    std::memcpy(&v1, &t[k * 0xc + 4], 4);
                    if (att >= nA || !seen.insert(att).second) continue;
                    if (v1 > 0) pairs.push_back(wnames[w] + "#" + an[att]);
                }
            }
            if (!ok) res.notes.push_back("attachments: hash/row check failed");
            else {
                res.notes.push_back(note("attachments", std::to_string(pairs.size()) + " weapon#attachment pairs from " +
                                                            std::to_string(nA) + " attachments"));
                res.groups["attachments"] = pairs;
            }
        }
    }

    // --- records with a parallel names vector and the hash at rec+0 ---
    auto parallel = [&](const char* what, std::uint64_t rec_at, std::size_t stride, std::uint64_t names_at,
                        int skip_off, bool skip_bit0, std::vector<std::string>& out) {
        std::uint64_t rb;
        std::size_t n;
        std::vector<std::string> nm;
        if (!r.vec(A + rec_at, stride, rb, n) || !r.names(A + names_at, n, nm)) {
            res.notes.push_back(note(what, "layout check failed"));
            return;
        }
        std::vector<std::string> got;
        for (std::size_t i = 0; i < n; ++i) {
            std::uint32_t h;
            if (!r.get(rb + i * stride, h) || h != fnv1a(nm[i])) {
                res.notes.push_back(note(what, "hash self-check failed"));
                return;
            }
            if (skip_off >= 0) {
                std::uint32_t f;
                if (!r.get(rb + i * stride + static_cast<std::uint64_t>(skip_off), f)) { res.notes.push_back(note(what, "unreadable")); return; }
                if (skip_bit0 ? (f & 1) : (f != 0)) continue; // free by default: already owned
            }
            got.push_back(nm[i]);
        }
        res.notes.push_back(note(what, std::to_string(got.size()) + " of " + std::to_string(n)));
        out.insert(out.end(), got.begin(), got.end());
    };
    // --- records with the name std::string inside (rec+0x10) and the hash at rec+8 ---
    auto inline_named = [&](const char* what, std::uint64_t rec_at, std::size_t stride, std::vector<std::string>& out) {
        std::uint64_t rb;
        std::size_t n;
        if (!r.vec(A + rec_at, stride, rb, n)) { res.notes.push_back(note(what, "layout check failed")); return; }
        std::vector<std::string> got;
        for (std::size_t i = 0; i < n; ++i) {
            std::uint64_t e = rb + i * stride;
            std::string nm;
            std::uint32_t h;
            unsigned char dflt, hidden;
            if (!r.str(e + 0x10, nm) || !r.get(e + 8, h) || h != fnv1a(nm) || !r.get(e + 0x39, dflt) ||
                !r.get(e + 0x40, hidden)) {
                res.notes.push_back(note(what, "record check failed"));
                return;
            }
            if (dflt || hidden) continue; // default-owned, or hidden from the menus
            got.push_back(nm);
        }
        res.notes.push_back(note(what, std::to_string(got.size()) + " of " + std::to_string(n)));
        out.insert(out.end(), got.begin(), got.end());
    };

    std::vector<std::string> camos, gear;
    parallel("camos", 0x288, 0x70, 0x2a0, 0x4c, true, camos);     // rec+0x4c bit0 = free
    parallel("masks", 0x258, 0x90, 0x270, -1, false, gear);       // no default flag
    parallel("trinkets", 0x2f8, 0x40, 0x310, 0x2c, false, gear);  // rec+0x2c != 0 = free
    inline_named("body pieces", 0x18, 0x90, gear);
    inline_named("body camos", 0x0, 0x98, gear);
    if (!camos.empty()) res.groups["camos"] = camos;
    if (!gear.empty()) res.groups["gear"] = gear;

    // --- killsigs: M+0x1a8 count, M+0x1b0 array (stride 0x50): name std::string at +0,
    // item hash +0x18, unlock condition hash +0x20 ("none" = free).
    if (M >= 0x1000) {
        std::int32_t n = 0;
        std::uint64_t arr = 0;
        std::vector<std::string> ks;
        bool ok = r.get(M + 0x1a8, n) && r.get(M + 0x1b0, arr) && n >= 0 && n <= 4096 && (n == 0 || arr >= 0x1000);
        const std::uint32_t none = fnv1a("none");
        for (std::int32_t i = 0; ok && i < n; ++i) {
            std::uint64_t e = arr + 0x50ull * static_cast<std::uint64_t>(i);
            std::string nm;
            std::uint32_t h, cond;
            ok = r.str(e, nm) && r.get(e + 0x18, h) && r.get(e + 0x20, cond) && h == fnv1a(nm);
            if (ok && cond != none) ks.push_back(nm);
        }
        if (!ok) res.notes.push_back("killsigs: check failed");
        else {
            res.notes.push_back(note("killsigs", std::to_string(ks.size()) + " of " + std::to_string(n)));
            if (!ks.empty()) res.groups["killsigs"] = ks;
        }
    }
    return res;
}

} // namespace itemdump
} // namespace mc5
