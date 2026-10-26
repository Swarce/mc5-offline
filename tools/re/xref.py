"""Fast ARM64 string xref index for an ELF .so: ADRP+ADD/LDR pairs -> target addresses,
mapped to containing functions (from .eh_frame via lief). Usage:
  python3 -I xref.py build <lib.so> <out.npz>
  python3 -I xref.py find <lib.so> <out.npz> <regex>   (prints string addr, text, referencing funcs)"""
import sys, re, bisect
import numpy as np
import lief

def load(lib):
    b = lief.parse(lib)
    text = b.get_section(".text")
    data = bytes(b.get_content_from_virtual_address(text.virtual_address, text.size))
    return b, text.virtual_address, data

def build(lib, out):
    b, base, data = load(lib)
    ins = np.frombuffer(data[:len(data)//4*4], dtype="<u4")
    pcs = base + 4*np.arange(len(ins), dtype=np.int64)
    adrp = np.nonzero((ins & 0x9F000000) == 0x90000000)[0]
    a = ins[adrp].astype(np.int64)
    rd = a & 0x1F
    immlo = (a >> 29) & 3
    immhi = (a >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    imm = np.where(imm & (1 << 20), imm - (1 << 21), imm)
    page = (pcs[adrp] & ~0xFFF) + (imm << 12)
    tgt_list, pc_list = [], []
    for k in (1, 2, 3, 4):
        j = adrp + k
        ok = j < len(ins)
        j2, ii, pg, r = j[ok], adrp[ok], page[ok], rd[ok]
        n = ins[j2].astype(np.int64)
        # ADD (immediate, 64-bit): sf=1 op=0 S=0 100010 sh imm12 Rn Rd
        isadd = (n & 0xFF800000) == 0x91000000
        rn = (n >> 5) & 0x1F
        sh = (n >> 22) & 1
        imm12 = (n >> 10) & 0xFFF
        m = isadd & (rn == r)
        tgt_list.append(pg[m] + (imm12[m] << (12 * sh[m])))
        pc_list.append(pcs[ii[m]])
        # LDR (unsigned offset, 64-bit) x: 0xF9400000
        isldr = (n & 0xFFC00000) == 0xF9400000
        m2 = isldr & (rn == r)
        tgt_list.append(pg[m2] + (imm12[m2] << 3))
        pc_list.append(pcs[ii[m2]])
    tg = np.concatenate(tgt_list); pc = np.concatenate(pc_list)
    starts = np.array(sorted(set(f.address for f in b.functions)), dtype=np.int64)
    np.savez(out, tgt=tg, pc=pc, starts=starts)
    print("refs", len(tg), "funcs", len(starts))

def strings_of(lib):
    b = lief.parse(lib)
    ro = b.get_section(".rodata")
    raw = bytes(b.get_content_from_virtual_address(ro.virtual_address, ro.size))
    for m in re.finditer(rb"[\x20-\x7e\t\n]{4,}", raw):
        yield ro.virtual_address + m.start(), m.group().decode("latin1")

def find(lib, npz, rx):
    z = np.load(npz)
    tg, pc, starts = z["tgt"], z["pc"], z["starts"]
    order = np.argsort(tg); tg = tg[order]; pc = pc[order]
    r = re.compile(rx)
    for addr, s in strings_of(lib):
        for mm in r.finditer(s):
            # string may be a substring inside a merged literal; compute the C-string start
            st = s.rfind("\0", 0, mm.start()) + 1
            a = addr + st
            lo, hi = np.searchsorted(tg, a), np.searchsorted(tg, a, side="right")
            fns = sorted(set(int(starts[np.searchsorted(starts, p, side="right") - 1]) for p in pc[lo:hi]))
            print(hex(a), repr(s[st:st+100]), " ".join(hex(f) for f in fns))
            break

if __name__ == "__main__":
    if sys.argv[1] == "build": build(sys.argv[2], sys.argv[3])
    else: find(sys.argv[2], sys.argv[3], sys.argv[4])
