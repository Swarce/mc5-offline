"""List Gaia (Federation) request builders in MC5's libMC5.so with their path literals and request keys.

Keys come from plain string literals and from the strings the binary builds one character at a time in static
initialisers (objstrings.tsv, produced by tools/re/objstr.py). Output: Markdown on stdout.
usage: python3 -I federation.py <export_dir> [lo_hex] [hi_hex]
"""
import os, re, sys

def main(export, lo='00d40000', hi='00e40000'):
    obj = {}
    for line in open(os.path.join(export, 'objstrings.tsv'), encoding='utf-8', errors='replace'):
        p = line.rstrip('\n').split('\t')
        if len(p) == 3:
            obj[p[0]] = p[2]
    funcs = {}
    d = os.path.join(export, 'decomp')
    for fn in sorted(os.listdir(d)):
        if not (lo[:4] <= fn[:4] <= hi[:4]):
            continue
        txt = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read()
        for block in txt.split('// ==== FUNC ')[1:]:
            addr = block.split('\n', 1)[0].rsplit('@ ', 1)[-1].strip()
            if lo <= addr < hi:
                funcs[addr] = block
    print('| Function | Method | Paths | Keys |\n|---|---|---|---|')
    for addr in sorted(funcs):
        b = funcs[addr]
        lits = re.findall(r'"([^"\\]{1,60})"', b)
        paths = [s for s in dict.fromkeys(lits) if s.startswith('/') or s.endswith('/')]
        if not paths:
            continue
        keys = [s for s in dict.fromkeys(lits) if re.fullmatch(r'[a-z_][a-z0-9_]{1,40}', s)]
        keys += [obj[k] for k in dict.fromkeys(re.findall(r'(DAT_01c[0-9a-f]{5})', b)) if k in obj]
        method = ','.join(m for m in ('GET', 'POST', 'PUT', 'DELETE') if f'"{m}"' in b) or '?'
        print(f"| G:0x{addr.lstrip('0')} | {method} | {' '.join(paths)} | {' '.join(dict.fromkeys(keys))[:300]} |")

if __name__ == '__main__':
    main(*sys.argv[1:])
