// test_filter_tramp.cpp — host checks for the arm64 filter-hook trampoline builder
// (hosts/embedded/filter_tramp.hpp). It is pure word building, so the encodings and the
// three ldr-literal offsets can be verified without a device. C++17.
#include "check.hpp"
#include "../hosts/embedded/filter_tramp.hpp"

#include <cstdint>

using namespace mc5;

namespace {

// Decode an ldr-literal (x) instruction's target word index: base word + imm19.
long ldr_literal_target(const std::uint32_t* w, int at) {
    std::uint32_t insn = w[at];
    // imm19 is bits [23:5]; sign-extend.
    long imm = static_cast<long>((insn >> 5) & 0x7ffff);
    if (imm & 0x40000) imm -= 0x80000;
    return at + imm;
}

void test_reloc_safe() {
    CHECK(tramp_reloc_safe(0xA94007E0u));  // ldp x0,x1,[sp] — fine
    CHECK(tramp_reloc_safe(0xD65F03C0u));  // ret — fine
    CHECK(tramp_reloc_safe(0x8B21C008u));  // add x8,x0,w1,sxtw — fine
    CHECK(!tramp_reloc_safe(0x14000002u)); // b — rejected
    CHECK(!tramp_reloc_safe(0x94000002u)); // bl — rejected
    CHECK(!tramp_reloc_safe(0x10000001u)); // adr — rejected
    CHECK(!tramp_reloc_safe(0x90000001u)); // adrp — rejected
    CHECK(!tramp_reloc_safe(0x54000001u)); // b.cond — rejected
    CHECK(!tramp_reloc_safe(0x34000001u)); // cbz — rejected
    CHECK(!tramp_reloc_safe(0x36000001u)); // tbz — rejected
    CHECK(!tramp_reloc_safe(0x18000001u)); // ldr literal — rejected
}

void test_build() {
    // A plausible 4-instruction prologue (all relocatable).
    const std::uint32_t orig[4] = {0xA9BE4FF4u, 0xA9017BFDu, 0x910043FDu, 0x2A0103F4u};
    const std::uint64_t cont = 0x7f00000000ull + 0xb20528ull;
    const std::uint64_t filt = 0x5500aabbccddull;
    std::uint32_t w[kFilterTrampWords] = {0};
    CHECK(build_filter_tramp(w, orig, cont, filt));

    // First instruction opens the frame; the save/restore pair is balanced.
    CHECK_EQ(w[0], 0xD10183FFu); // sub sp,sp,#0x60
    CHECK_EQ(w[6], 0xF9002BFFu); // str xzr,[sp,#0x50]  (*ret = 0)
    CHECK_EQ(w[7], 0x910143E4u); // add x4,sp,#0x50     (ret pointer)
    CHECK_EQ(w[9], 0xD63F0120u); // blr x9

    // The relocated original prologue sits just after the "run_original" label.
    for (int i = 0; i < 4; ++i) CHECK_EQ(w[21 + i], orig[i]);

    // The data pool holds cont then filter, each little-endian u64.
    const int pool = 28;
    std::uint64_t cont_rd = static_cast<std::uint64_t>(w[pool]) | (static_cast<std::uint64_t>(w[pool + 1]) << 32);
    std::uint64_t filt_rd = static_cast<std::uint64_t>(w[pool + 2]) | (static_cast<std::uint64_t>(w[pool + 3]) << 32);
    CHECK_EQ(cont_rd, cont);
    CHECK_EQ(filt_rd, filt);

    // The three ldr-literal loads must resolve to the right pool words.
    // ldr x9,=filter at word 8; ldr x16,=cont at word 25.
    CHECK_EQ(ldr_literal_target(w, 8), pool + 2); // filter
    CHECK_EQ(ldr_literal_target(w, 25), pool);    // cont
    // The cbz at word 15 jumps to the run_original label at word 19.
    std::uint32_t cbz = w[15];
    CHECK_EQ(cbz & 0xff00001fu, 0x34000009u); // cbz w9, ...
    long cbz_imm = static_cast<long>((cbz >> 5) & 0x7ffff);
    if (cbz_imm & 0x40000) cbz_imm -= 0x80000;
    CHECK_EQ(15 + cbz_imm, 19);
}

void test_rejects_pcrel_prologue() {
    const std::uint32_t bad[4] = {0x90000000u /*adrp*/, 0xA9017BFDu, 0x910043FDu, 0x2A0103F4u};
    std::uint32_t w[kFilterTrampWords] = {0};
    CHECK(!build_filter_tramp(w, bad, 0x1000, 0x2000));
}

} // namespace

int main() {
    test_reloc_safe();
    test_build();
    test_rejects_pcrel_prologue();
    if (mc5test::failures() == 0) std::fprintf(stderr, "filter_tramp: all checks passed\n");
    return mc5test::failures() ? 1 : 0;
}
