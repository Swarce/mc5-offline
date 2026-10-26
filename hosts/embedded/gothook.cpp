#include "gothook.hpp"

#include <cstdint>
#include <cstring>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#include "../../server/core/log.hpp"

// Bitness-correct relocation field accessors (no portable generic macro exists).
#if defined(__LP64__)
#define MC5_R_SYM(i) ELF64_R_SYM(i)
#define MC5_R_TYPE(i) ELF64_R_TYPE(i)
#else
#define MC5_R_SYM(i) ELF32_R_SYM(i)
#define MC5_R_TYPE(i) ELF32_R_TYPE(i)
#endif

namespace mc5 {

namespace {

// Relocation types that reference a symbol through a writable slot.
#if defined(__aarch64__)
constexpr unsigned kJumpSlot = R_AARCH64_JUMP_SLOT;
constexpr unsigned kGlobDat = R_AARCH64_GLOB_DAT;
constexpr unsigned kAbs = R_AARCH64_ABS64;
#elif defined(__arm__)
constexpr unsigned kJumpSlot = R_ARM_JUMP_SLOT;
constexpr unsigned kGlobDat = R_ARM_GLOB_DAT;
constexpr unsigned kAbs = R_ARM_ABS32;
#elif defined(__x86_64__)
constexpr unsigned kJumpSlot = R_X86_64_JUMP_SLOT;
constexpr unsigned kGlobDat = R_X86_64_GLOB_DAT;
constexpr unsigned kAbs = R_X86_64_64;
#else
constexpr unsigned kJumpSlot = 0xffffffff;
constexpr unsigned kGlobDat = 0xffffffff;
constexpr unsigned kAbs = 0xffffffff;
#endif

struct DynInfo {
    const char* strtab = nullptr;
    const ElfW(Sym)* symtab = nullptr;
    const ElfW(Rela)* rela = nullptr;   size_t rela_count = 0;   // .rela.dyn
    const ElfW(Rela)* jmprela = nullptr; size_t jmprela_count = 0; // .rela.plt (RELA)
    const ElfW(Rel)* rel = nullptr;     size_t rel_count = 0;     // .rel.dyn
    const ElfW(Rel)* jmprel = nullptr;  size_t jmprel_count = 0;  // .rel.plt (REL)
    long pltrel = 0;                    // DT_PLTREL: DT_RELA or DT_REL
};

// Resolve a .dynamic pointer to a runtime address. On bionic these are link-time
// vaddrs needing the load bias; when already relocated they are >= base.
inline uintptr_t fix(uintptr_t base, uintptr_t p) {
    return p >= base ? p : base + p;
}

bool read_dynamic(const dl_phdr_info* info, DynInfo& out) {
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return false;

    uintptr_t base = info->dlpi_addr;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ElfW(Rela));
    size_t relsz = 0, relent = sizeof(ElfW(Rel));
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_STRTAB: out.strtab = reinterpret_cast<const char*>(fix(base, dyn->d_un.d_ptr)); break;
            case DT_SYMTAB: out.symtab = reinterpret_cast<const ElfW(Sym)*>(fix(base, dyn->d_un.d_ptr)); break;
            case DT_JMPREL: out.jmprela = reinterpret_cast<const ElfW(Rela)*>(fix(base, dyn->d_un.d_ptr)); break;
            case DT_PLTRELSZ: pltrelsz = dyn->d_un.d_val; break;
            case DT_PLTREL: out.pltrel = dyn->d_un.d_val; break;
            case DT_RELA: out.rela = reinterpret_cast<const ElfW(Rela)*>(fix(base, dyn->d_un.d_ptr)); break;
            case DT_RELASZ: relasz = dyn->d_un.d_val; break;
            case DT_RELAENT: relaent = dyn->d_un.d_val; break;
            case DT_REL: out.rel = reinterpret_cast<const ElfW(Rel)*>(fix(base, dyn->d_un.d_ptr)); break;
            case DT_RELSZ: relsz = dyn->d_un.d_val; break;
            case DT_RELENT: relent = dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (!out.strtab || !out.symtab) return false;
    if (relaent == 0) relaent = sizeof(ElfW(Rela));
    if (relent == 0) relent = sizeof(ElfW(Rel));
    if (out.rela) out.rela_count = relasz / relaent;
    if (out.rel) out.rel_count = relsz / relent;
    if (out.pltrel == DT_RELA) { out.jmprela_count = pltrelsz / relaent; out.jmprela = reinterpret_cast<const ElfW(Rela)*>(out.jmprela); }
    else if (out.pltrel == DT_REL) { out.jmprel = reinterpret_cast<const ElfW(Rel)*>(out.jmprela); out.jmprel_count = pltrelsz / relent; out.jmprela = nullptr; }
    return true;
}

bool write_slot(uintptr_t slot, void* value, void** out_original) {
    long pagesz = sysconf(_SC_PAGESIZE);
    uintptr_t page = slot & ~(static_cast<uintptr_t>(pagesz) - 1);
    if (mprotect(reinterpret_cast<void*>(page), pagesz, PROT_READ | PROT_WRITE) != 0) return false;
    void** p = reinterpret_cast<void**>(slot);
    if (out_original && *out_original == nullptr) *out_original = *p;
    *p = value;
    // Leave the page writable (bionic GOT is RW anyway); best-effort restore.
    mprotect(reinterpret_cast<void*>(page), pagesz, PROT_READ | PROT_WRITE);
    __builtin___clear_cache(reinterpret_cast<char*>(slot), reinterpret_cast<char*>(slot + sizeof(void*)));
    return true;
}

template <typename RelT>
int patch_relocs(uintptr_t base, const DynInfo& di, const RelT* relocs, size_t count,
                 const char* symbol, void* repl, void** out_original) {
    int patched = 0;
    for (size_t i = 0; i < count; ++i) {
        const RelT& r = relocs[i];
        unsigned type = MC5_R_TYPE(r.r_info);
        if (type != kJumpSlot && type != kGlobDat && type != kAbs) continue;
        unsigned symidx = MC5_R_SYM(r.r_info);
        const ElfW(Sym)& sym = di.symtab[symidx];
        const char* name = di.strtab + sym.st_name;
        if (std::strcmp(name, symbol) != 0) continue;
        if (write_slot(base + r.r_offset, repl, out_original)) ++patched;
    }
    return patched;
}

struct HookCtx {
    const char* so_substr;
    const char* symbol;
    void* repl;
    void** out_original;
    int patched;
    bool only_presence; // for so_loaded()
    bool present;
};

int iterate_cb(dl_phdr_info* info, size_t, void* data) {
    auto* ctx = static_cast<HookCtx*>(data);
    const char* name = info->dlpi_name ? info->dlpi_name : "";
    if (!std::strstr(name, ctx->so_substr)) return 0;
    if (ctx->only_presence) { ctx->present = true; return 1; }

    DynInfo di;
    if (!read_dynamic(info, di)) return 0;
    uintptr_t base = info->dlpi_addr;
    if (di.jmprela) ctx->patched += patch_relocs(base, di, di.jmprela, di.jmprela_count, ctx->symbol, ctx->repl, ctx->out_original);
    if (di.jmprel) ctx->patched += patch_relocs(base, di, di.jmprel, di.jmprel_count, ctx->symbol, ctx->repl, ctx->out_original);
    if (di.rela) ctx->patched += patch_relocs(base, di, di.rela, di.rela_count, ctx->symbol, ctx->repl, ctx->out_original);
    if (di.rel) ctx->patched += patch_relocs(base, di, di.rel, di.rel_count, ctx->symbol, ctx->repl, ctx->out_original);
    return 0; // keep going: patch every matching object
}

} // namespace

bool so_loaded(const char* so_substr) {
    HookCtx ctx{so_substr, nullptr, nullptr, nullptr, 0, true, false};
    dl_iterate_phdr(iterate_cb, &ctx);
    return ctx.present;
}

int got_hook(const char* so_substr, const char* symbol, void* replacement, void** out_original) {
    HookCtx ctx{so_substr, symbol, replacement, out_original, 0, false, false};
    dl_iterate_phdr(iterate_cb, &ctx);
    return ctx.patched;
}

} // namespace mc5
