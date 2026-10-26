"""ARM64 BL call index. python3 -I calls.py <lib.so> <target-hex|symbol-substring> ...
Prints caller function starts (eh_frame) and call sites for BL to the target (or to PLT stubs of imports)."""
import sys, bisect
import numpy as np, lief
lib = sys.argv[1]
b = lief.parse(lib)
text = b.get_section(".text")
base = text.virtual_address
data = bytes(b.get_content_from_virtual_address(base, text.size))
ins = np.frombuffer(data[:len(data)//4*4], dtype="<u4")
idx = np.nonzero((ins & 0xFC000000) == 0x94000000)[0]
imm = (ins[idx] & 0x03FFFFFF).astype(np.int64)
imm = np.where(imm & (1 << 25), imm - (1 << 26), imm)
pcs = base + 4 * idx.astype(np.int64)
tg = pcs + imm * 4
starts = np.array(sorted(set(f.address for f in b.functions)), dtype=np.int64)
# PLT stubs: map import name -> stub address via .plt layout (16-byte entries after 32-byte header)
plt = b.get_section(".plt")
names = {}
rel = list(b.pltgot_relocations)
for i, r in enumerate(rel):
    if r.has_symbol:
        names[r.symbol.name] = plt.virtual_address + 32 + 16 * i
dyn = {}
for s in b.dynamic_symbols:
    if s.value: dyn.setdefault(s.name, s.value)
for q in sys.argv[2:]:
    if q.startswith("0x"): targets = [(q, int(q, 16))]
    else: targets = [(n, a) for n, a in list(names.items()) + list(dyn.items()) if q in n]
    for n, a in targets[:20]:
        sites = pcs[tg == a]
        fns = sorted(set(int(starts[np.searchsorted(starts, p, side="right") - 1]) for p in sites))
        print(f"{n} @ {a:#x}: {len(sites)} calls from {len(fns)} funcs:", " ".join(hex(f) for f in fns[:60]))
