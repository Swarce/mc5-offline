// lz4.hpp — a small, self-written LZ4 *block* compressor and decompressor.
//
// The TS frames 0x27 (TCP_Profile) and 0x46 (TCP_Inventory_Changes) carry
// [u32 BE clen][LZ4 block] that the client inflates into a 1 MB buffer. A profile
// after an unlock code holds thousands of item names, far past the 64 KB frame
// limit, so the server needs real compression (JSON compresses ~10x).
//
// Greedy hash-chain matcher (4-byte hash, depth 32, 64 KB window) that honours the LZ4
// block end rules: the last 5 bytes are always literals and no match starts within
// the last 12 bytes (MFLIMIT). decompress() is a strict, bounds-checked decoder
// used by the unit tests to round-trip the output. C++17, header-only.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace mc5 {
namespace lz4 {

namespace detail {
inline std::uint32_t read32(const unsigned char* p) {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
inline void put_len(std::string& o, std::size_t n) {
    while (n >= 255) { o.push_back(static_cast<char>(255)); n -= 255; }
    o.push_back(static_cast<char>(n));
}
inline void emit(std::string& o, const unsigned char* lit, std::size_t nlit, std::size_t off,
                 std::size_t mlen /* 0 = last literals-only sequence */) {
    std::size_t ml = mlen ? mlen - 4 : 0;
    unsigned tok = static_cast<unsigned>((nlit < 15 ? nlit : 15) << 4);
    if (mlen) tok |= static_cast<unsigned>(ml < 15 ? ml : 15);
    o.push_back(static_cast<char>(tok));
    if (nlit >= 15) put_len(o, nlit - 15);
    o.append(reinterpret_cast<const char*>(lit), nlit);
    if (!mlen) return;
    o.push_back(static_cast<char>(off & 0xff));
    o.push_back(static_cast<char>((off >> 8) & 0xff));
    if (ml >= 15) put_len(o, ml - 15);
}
} // namespace detail

inline std::string compress(const std::string& in) {
    const unsigned char* src = reinterpret_cast<const unsigned char*>(in.data());
    const std::size_t n = in.size();
    std::string out;
    out.reserve(n / 3 + 16);
    constexpr std::size_t kMinLen = 4, kLastLiterals = 5, kMfLimit = 12;
    constexpr int kHashBits = 16, kDepth = 32;
    // Hash chains (head per 4-byte hash, prev per position): longest match among the
    // last kDepth candidates inside the 64 KB window.
    std::vector<std::int32_t> head(std::size_t(1) << kHashBits, -1);
    std::vector<std::int32_t> prev(n, -1);
    auto hash = [&](std::size_t i) {
        return (detail::read32(src + i) * 2654435761u) >> (32 - kHashBits);
    };
    auto insert = [&](std::size_t i) {
        std::uint32_t h = hash(i);
        prev[i] = head[h];
        head[h] = static_cast<std::int32_t>(i);
    };
    std::size_t anchor = 0, i = 0;
    if (n >= kMfLimit + 1) {
        const std::size_t match_limit = n - kMfLimit;  // last match start (exclusive)
        const std::size_t end_limit = n - kLastLiterals; // a match may not extend past this
        while (i < match_limit) {
            std::size_t best_len = 0, best_off = 0;
            std::int32_t cand = head[hash(i)];
            for (int d = 0; d < kDepth && cand >= 0; ++d, cand = prev[static_cast<std::size_t>(cand)]) {
                std::size_t c = static_cast<std::size_t>(cand);
                if (i - c > 0xFFFF) break;
                if (detail::read32(src + c) != detail::read32(src + i)) continue;
                std::size_t len = kMinLen;
                while (i + len < end_limit && src[c + len] == src[i + len]) ++len;
                if (len > best_len) { best_len = len; best_off = i - c; }
            }
            insert(i);
            if (best_len >= kMinLen) {
                detail::emit(out, src + anchor, i - anchor, best_off, best_len);
                for (std::size_t k = i + 1; k < i + best_len && k < match_limit; ++k) insert(k);
                i += best_len;
                anchor = i;
                continue;
            }
            ++i;
        }
    }
    detail::emit(out, src + anchor, n - anchor, 0, 0);
    return out;
}

// Strict decoder: returns false on any malformed input or if the output would
// exceed max_out.
inline bool decompress(const std::string& in, std::string& out, std::size_t max_out) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(in.data());
    const unsigned char* e = p + in.size();
    out.clear();
    while (p < e) {
        unsigned tok = *p++;
        std::size_t lit = tok >> 4;
        if (lit == 15) {
            unsigned b;
            do { if (p >= e) return false; b = *p++; lit += b; } while (b == 255);
        }
        if (static_cast<std::size_t>(e - p) < lit || out.size() + lit > max_out) return false;
        out.append(reinterpret_cast<const char*>(p), lit);
        p += lit;
        if (p == e) return true; // last sequence: literals only
        if (e - p < 2) return false;
        std::size_t off = p[0] | (static_cast<std::size_t>(p[1]) << 8);
        p += 2;
        if (off == 0 || off > out.size()) return false;
        std::size_t ml = (tok & 15);
        if (ml == 15) {
            unsigned b;
            do { if (p >= e) return false; b = *p++; ml += b; } while (b == 255);
        }
        ml += 4;
        if (out.size() + ml > max_out) return false;
        std::size_t from = out.size() - off;
        for (std::size_t k = 0; k < ml; ++k) out.push_back(out[from + k]); // overlap-safe
    }
    return in.empty() ? false : true;
}

} // namespace lz4
} // namespace mc5
