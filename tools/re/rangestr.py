"""Strings referenced from code in [lo, hi): python3 -I rangestr.py <lib> <xref.npz> <lo> <hi>"""
import sys, numpy as np, lief
lib, npz, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4], 16)
z = np.load(npz); tg, pc, starts = z["tgt"], z["pc"], z["starts"]
m = (pc >= lo) & (pc < hi)
b = lief.parse(lib)
ro = b.get_section(".rodata"); rlo, rhi = ro.virtual_address, ro.virtual_address + ro.size
raw = bytes(b.get_content_from_virtual_address(rlo, ro.size))
out = {}
for t, p in zip(tg[m], pc[m]):
    if rlo <= t < rhi:
        s = raw[t - rlo: t - rlo + 160].split(b"\0")[0]
        try: s = s.decode()
        except Exception: continue
        if len(s) >= 2 and all(32 <= ord(c) < 127 or c in "\t\n" for c in s):
            f = int(starts[np.searchsorted(starts, p, side="right") - 1])
            out.setdefault(f, []).append(s)
for f in sorted(out):
    print(hex(f), " | ".join(dict.fromkeys(out[f]))[:600])
