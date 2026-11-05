// ts_codec.hpp — TS meta-channel framing helpers shared by meta.cpp, the profile
// store and the unit tests.
//
// Frames are [type u8][len u16 BE incl. the 3-byte header][payload], big-endian.
// str = u16 BE length + bytes; blob32 = u32 BE length + bytes. Exceptions: the f32
// in 0x45/0x46 is little-endian (read by 0x9cf858), and the per-weapon/achievement
// records inside 0x11 blobs are little-endian structs.
//
// Reimplemented from the client's own readers/writers (0x9cf4c0/0x9cf5a0/0x9cfb80/
// 0x9cfcb8 read; 0x9cf3a8/0x9cf520/0x9cfae0/0x9cfc20 write). C++17, header-only.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>

namespace mc5 {
namespace ts {

inline void put_u8(std::string& s, unsigned v) { s.push_back(static_cast<char>(v & 0xff)); }
inline void put_u16(std::string& s, std::uint16_t v) {
    s.push_back(static_cast<char>((v >> 8) & 0xff));
    s.push_back(static_cast<char>(v & 0xff));
}
inline void put_u32(std::string& s, std::uint32_t v) {
    for (int sh = 24; sh >= 0; sh -= 8) s.push_back(static_cast<char>((v >> sh) & 0xff));
}
inline void put_f32le(std::string& s, float f) {
    std::uint32_t v;
    std::memcpy(&v, &f, 4);
    for (int sh = 0; sh <= 24; sh += 8) s.push_back(static_cast<char>((v >> sh) & 0xff));
}
inline std::string str16(const std::string& d) {
    std::string o;
    put_u16(o, static_cast<std::uint16_t>(d.size()));
    o += d;
    return o;
}
inline std::string blob32(const std::string& d) {
    std::string o;
    put_u32(o, static_cast<std::uint32_t>(d.size()));
    o += d;
    return o;
}
// Largest payload one frame can carry (u16 length includes the 3-byte header).
constexpr std::size_t kMaxPayload = 0xFFFF - 3;
inline std::string frame(std::uint8_t type, const std::string& payload) {
    std::string o;
    o.push_back(static_cast<char>(type));
    put_u16(o, static_cast<std::uint16_t>(3 + payload.size()));
    o += payload;
    return o;
}

// FNV-1a-32 over signed chars, the client's item/key hash (0x4fcc88; basis
// 0x811c9dc5, prime 0x01000193). The client sign-extends each byte (sxtb at
// 0x4fcca8) before the XOR, which matters for bytes >= 0x80; reproduce that exactly.
// FNV("Venice_01_Intro") = 363515348 (the 0x10 "node"), FNV("credits") = 1358361813.
inline std::uint32_t fnv1a(const std::string& s) {
    std::uint32_t h = 0x811c9dc5u;
    for (char c : s) {
        h ^= static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<signed char>(c)));
        h *= 0x01000193u;
    }
    return h;
}

// Bounds-checked big-endian reader over a client payload. Any overrun sets ok=false
// and every later read returns 0/"" (callers check ok at section boundaries).
struct Reader {
    const std::string& d;
    std::size_t p = 0;
    bool ok = true;
    explicit Reader(const std::string& s) : d(s) {}
    std::size_t left() const { return p <= d.size() ? d.size() - p : 0; }
    bool need(std::size_t n) { if (!ok || n > left()) ok = false; return ok; }
    unsigned u8() { if (!need(1)) return 0; return static_cast<unsigned char>(d[p++]); }
    unsigned u16() { if (!need(2)) return 0; unsigned v = (static_cast<unsigned char>(d[p]) << 8) | static_cast<unsigned char>(d[p + 1]); p += 2; return v; }
    std::uint32_t u32() {
        if (!need(4)) return 0;
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | static_cast<unsigned char>(d[p++]);
        return v;
    }
    std::string bytes(std::size_t n) { if (!need(n)) return std::string(); std::string s = d.substr(p, n); p += n; return s; }
    std::string str() { std::size_t n = u16(); return ok ? bytes(n) : std::string(); }
    std::string blob() { std::size_t n = u32(); return ok ? bytes(n) : std::string(); }
    // Peek a u16 length without consuming it (for boundary validation).
    bool peek_u16(unsigned& v) const {
        if (!ok || p + 2 > d.size()) return false;
        v = (static_cast<unsigned char>(d[p]) << 8) | static_cast<unsigned char>(d[p + 1]);
        return true;
    }
};

inline std::uint32_t le32(const std::string& b, std::size_t off) {
    if (b.size() < off + 4) return 0;
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | static_cast<unsigned char>(b[off + i]);
    return v;
}

} // namespace ts
} // namespace mc5
