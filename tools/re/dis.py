"""Annotated ARM64 disassembly of one function (bounds from eh_frame) with string/xref comments.
Usage: python3 -I dis.py <lib.so> <hexaddr> [maxinsns]"""
import sys, re, bisect
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
lib, addr = sys.argv[1], int(sys.argv[2], 16)
maxn = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
b = lief.parse(lib)
fns = {f.address: f.size for f in b.functions}
starts = sorted(fns)
i = bisect.bisect_right(starts, addr) - 1
fa = starts[i]; size = fns[fa] or 0x400
code = bytes(b.get_content_from_virtual_address(fa, size))
dyn = {}
for s in b.dynamic_symbols:
    if s.value: dyn[s.value] = s.demangled_name or s.name
plt = {}
for r in b.pltgot_relocations:
    if r.has_symbol: plt[r.address] = r.symbol.name
ro = b.get_section(".rodata")
def cstr(a):
    if ro.virtual_address <= a < ro.virtual_address + ro.size:
        raw = bytes(b.get_content_from_virtual_address(a, 120))
        s = raw.split(b"\0")[0]
        try:
            t = s.decode()
            if t and all(32 <= ord(c) < 127 or c in "\t\n" for c in t): return repr(t)
        except Exception: pass
    return None
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
regs = {}
print(f"// func {fa:#x} size {size:#x} {dyn.get(fa,'')}")
n = 0
for ins in md.disasm(code, fa):
    c = ""
    if ins.mnemonic == "adrp":
        rd, imm = ins.op_str.split(", ")
        regs[rd] = int(imm.replace("#", ""), 16)
    elif ins.mnemonic == "add" and "#" in ins.op_str:
        ops = [o.strip() for o in ins.op_str.split(",")]
        if len(ops) >= 3 and ops[1] in regs:
            try:
                t = regs[ops[1]] + int(ops[2].replace("#", ""), 16 if "0x" in ops[2] else 10)
                s = cstr(t)
                c = f"  ; {t:#x} " + (s or dyn.get(t, ""))
            except Exception: pass
    elif ins.mnemonic in ("bl", "b"):
        try:
            t = int(ins.op_str.replace("#", ""), 16)
            c = "  ; " + dyn.get(t, "")
        except Exception: pass
    print(f"{ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}{c}")
    n += 1
    if n >= maxn: break
