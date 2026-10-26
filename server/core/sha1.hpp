// Compact SHA-1 for deriving stable account ids from credentials.
//
// MCVS Offline made fed ids deterministic (account = hex(sha1(credential))[:24]) so
// independent per-device servers can agree on identities for LAN/internet play
// without shared state. We keep that scheme. SHA-1 is used only as a stable,
// collision-resistant-enough id derivation here, not for security.
//
// C++17, header-only, no dependencies.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>

namespace mc5 {

class Sha1 {
public:
    Sha1() { reset(); }

    void update(const void* data, std::size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        total_ += len;
        while (len > 0) {
            std::size_t take = 64 - buf_len_;
            if (take > len) take = len;
            std::memcpy(buf_ + buf_len_, p, take);
            buf_len_ += take;
            p += take;
            len -= take;
            if (buf_len_ == 64) { process(buf_); buf_len_ = 0; }
        }
    }

    std::string hex_digest() {
        uint64_t bits = total_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len_ != 56) update(&zero, 1);
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; ++i) lenbuf[i] = static_cast<uint8_t>((bits >> (56 - 8 * i)) & 0xff);
        update(lenbuf, 8);

        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(40);
        for (int i = 0; i < 5; ++i) {
            for (int s = 28; s >= 0; s -= 4) out += hex[(h_[i] >> s) & 0xf];
        }
        return out;
    }

    static std::string hex(const std::string& s) {
        Sha1 h;
        h.update(s.data(), s.size());
        return h.hex_digest();
    }

private:
    void reset() {
        h_[0] = 0x67452301; h_[1] = 0xEFCDAB89; h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476; h_[4] = 0xC3D2E1F0;
        total_ = 0;
        buf_len_ = 0;
    }

    static uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

    void process(const uint8_t* block) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t tmp = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = tmp;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
    }

    uint32_t h_[5];
    uint64_t total_;
    uint8_t buf_[64];
    std::size_t buf_len_;
};

} // namespace mc5
