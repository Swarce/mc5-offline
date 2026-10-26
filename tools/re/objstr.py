"""Decode char-by-char obfuscated static strings: FUN_00541b98(&local,CH) sequences -> target DAT_.
python3 -I objstr.py <decomp_dir>  prints: DAT_addr<TAB>init_func<TAB>string"""
import os, re, sys
d = sys.argv[1]
call = re.compile(r"FUN_00541b98\(&local_[0-9a-f]+,(0x[0-9a-f]+|\d+)\)")
tgt = re.compile(r"FUN_[0-9a-f]+\(&(DAT_[0-9a-f]+),&local_[0-9a-f]+\)")
for fn in sorted(os.listdir(d)):
    txt = open(os.path.join(d, fn), encoding="utf-8", errors="replace").read()
    for block in txt.split("// ==== FUNC ")[1:]:
        if "FUN_00541b98" not in block: continue
        head = block.split("\n", 1)[0]
        chars, out = [], []
        for line in block.split("\n"):
            m = call.search(line)
            if m:
                chars.append(int(m.group(1), 0)); continue
            t = tgt.search(line)
            if t and chars:
                out.append((t.group(1), "".join(chr(c) if 32 <= c < 127 else "?" for c in chars)))
                chars = []
        for dat, s in out:
            print(f"{dat}\t{head.split(' @ ')[-1]}\t{s}")
