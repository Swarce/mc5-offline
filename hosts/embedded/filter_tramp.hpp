// filter_tramp.hpp — the arm64 "filter" trampoline used by install_filter_hook().
//
// A filter hook puts a C predicate in front of a libMC5 function:
//   int filter(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t* ret);
// It returns 0 to let the original function run untouched (its first 4 instructions,
// relocated, then a jump to vaddr+16), or non-zero to return *ret to the caller at once
// without running the original. The trampoline saves and restores x0-x8 and x30. The
// filter is a normal AAPCS64 function, so v8-v15 are preserved; v0-v7/v16-v31 are dead at
// a call boundary unless the hooked function takes FP arguments (none of ours do).
//
// Pure word building, no system calls, so tests/test_filter_tramp.cpp checks the
// encodings on the host. C++17.
#pragma once

#include <cstddef>
#include <cstdint>

namespace mc5 {

// PC-relative instructions cannot be moved into the trampoline.
inline bool tramp_reloc_safe(std::uint32_t w) {
    if ((w & 0x1f000000u) == 0x10000000u) return false; // ADR/ADRP
    if ((w & 0xfc000000u) == 0x14000000u) return false; // B
    if ((w & 0xfc000000u) == 0x94000000u) return false; // BL
    if ((w & 0xff000010u) == 0x54000000u) return false; // B.cond
    if ((w & 0x7e000000u) == 0x34000000u) return false; // CBZ/CBNZ
    if ((w & 0x7e000000u) == 0x36000000u) return false; // TBZ/TBNZ
    if ((w & 0x3b000000u) == 0x18000000u) return false; // LDR/LDRSW (literal)
    return true;
}

constexpr std::size_t kFilterTrampWords = 32; // code (28 incl. pad) + 2 x u64 pool

// Writes the trampoline into w[0..kFilterTrampWords). `cont` = vaddr+16 (absolute),
// `filter` = the predicate's address. Returns false if an original instruction is not
// relocatable (nothing should be patched then).
inline bool build_filter_tramp(std::uint32_t* w, const std::uint32_t orig[4], std::uint64_t cont,
                               std::uint64_t filter) {
    for (int i = 0; i < 4; ++i)
        if (!tramp_reloc_safe(orig[i])) return false;
    int n = 0;
    w[n++] = 0xD10183FFu; //  0 sub  sp, sp, #0x60
    w[n++] = 0xA90007E0u; //  1 stp  x0, x1, [sp]
    w[n++] = 0xA9010FE2u; //  2 stp  x2, x3, [sp, #0x10]
    w[n++] = 0xA90217E4u; //  3 stp  x4, x5, [sp, #0x20]
    w[n++] = 0xA9031FE6u; //  4 stp  x6, x7, [sp, #0x30]
    w[n++] = 0xA9047BE8u; //  5 stp  x8, x30, [sp, #0x40]
    w[n++] = 0xF9002BFFu; //  6 str  xzr, [sp, #0x50]      (*ret = 0)
    w[n++] = 0x910143E4u; //  7 add  x4, sp, #0x50         (ret pointer; x0-x3 unchanged)
    const int i_ldr_filter = n;
    w[n++] = 0x58000009u; //  8 ldr  x9, =filter           (imm19 patched below)
    w[n++] = 0xD63F0120u; //  9 blr  x9
    w[n++] = 0x2A0003E9u; // 10 mov  w9, w0
    w[n++] = 0xA9410FE2u; // 11 ldp  x2, x3, [sp, #0x10]
    w[n++] = 0xA94217E4u; // 12 ldp  x4, x5, [sp, #0x20]
    w[n++] = 0xA9431FE6u; // 13 ldp  x6, x7, [sp, #0x30]
    w[n++] = 0xA9447BE8u; // 14 ldp  x8, x30, [sp, #0x40]
    const int i_cbz = n;
    w[n++] = 0x34000009u; // 15 cbz  w9, run_original     (imm19 patched below)
    w[n++] = 0xF9402BE0u; // 16 ldr  x0, [sp, #0x50]       (handled: return *ret)
    w[n++] = 0x910183FFu; // 17 add  sp, sp, #0x60
    w[n++] = 0xD65F03C0u; // 18 ret
    const int i_orig = n;
    w[n++] = 0xA94007E0u; // 19 ldp  x0, x1, [sp]           (run_original)
    w[n++] = 0x910183FFu; // 20 add  sp, sp, #0x60
    for (int i = 0; i < 4; ++i) w[n++] = orig[i]; // 21..24 relocated prologue
    const int i_ldr_cont = n;
    w[n++] = 0x58000010u; // 25 ldr  x16, =cont            (imm19 patched below)
    w[n++] = 0xD61F0200u; // 26 br   x16
    while (n & 1) w[n++] = 0xD503201Fu; // 27 nop (8-byte align the pool)
    const int pool = n;                  // 28: cont, 30: filter
    w[pool + 0] = static_cast<std::uint32_t>(cont);
    w[pool + 1] = static_cast<std::uint32_t>(cont >> 32);
    w[pool + 2] = static_cast<std::uint32_t>(filter);
    w[pool + 3] = static_cast<std::uint32_t>(filter >> 32);
    auto imm19 = [](int from, int to) { return (static_cast<std::uint32_t>(to - from) & 0x7ffffu) << 5; };
    w[i_ldr_filter] |= imm19(i_ldr_filter, pool + 2);
    w[i_cbz] |= imm19(i_cbz, i_orig);
    w[i_ldr_cont] |= imm19(i_ldr_cont, pool);
    return pool + 4 == static_cast<int>(kFilterTrampWords);
}

} // namespace mc5
