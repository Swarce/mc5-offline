"""Minimal AS3 (ABC) reader/disassembler for uncompressed SWF (FWS) files.

Usage:
  python3 -I abcdis.py <file.swf> strings <regex>         # list cpool strings matching
  python3 -I abcdis.py <file.swf> uses <regex>             # methods referencing matching strings/names
  python3 -I abcdis.py <file.swf> dis <method_index>       # disassemble one method body

Written for interoperability analysis of the player's own MC5 UI assets (the game's
own Scaleform SWFs). Pure python, no third-party code.
"""
import re
import struct
import sys

OPS = {
    # name, operand kinds: u30 / s24 / u8 / lookupswitch
    0x01: ("bkpt", ""), 0x02: ("nop", ""), 0x03: ("throw", ""),
    0x04: ("getsuper", "m"), 0x05: ("setsuper", "m"), 0x06: ("dxns", "s"), 0x07: ("dxnslate", ""),
    0x08: ("kill", "u"), 0x09: ("label", ""),
    0x0C: ("ifnlt", "j"), 0x0D: ("ifnle", "j"), 0x0E: ("ifngt", "j"), 0x0F: ("ifnge", "j"),
    0x10: ("jump", "j"), 0x11: ("iftrue", "j"), 0x12: ("iffalse", "j"), 0x13: ("ifeq", "j"),
    0x14: ("ifne", "j"), 0x15: ("iflt", "j"), 0x16: ("ifle", "j"), 0x17: ("ifgt", "j"),
    0x18: ("ifge", "j"), 0x19: ("ifstricteq", "j"), 0x1A: ("ifstrictne", "j"),
    0x1B: ("lookupswitch", "L"), 0x1C: ("pushwith", ""), 0x1D: ("popscope", ""),
    0x1E: ("nextname", ""), 0x1F: ("hasnext", ""), 0x20: ("pushnull", ""), 0x21: ("pushundefined", ""),
    0x23: ("nextvalue", ""), 0x24: ("pushbyte", "b"), 0x25: ("pushshort", "u"), 0x26: ("pushtrue", ""),
    0x27: ("pushfalse", ""), 0x28: ("pushnan", ""), 0x29: ("pop", ""), 0x2A: ("dup", ""),
    0x2B: ("swap", ""), 0x2C: ("pushstring", "s"), 0x2D: ("pushint", "i"), 0x2E: ("pushuint", "U"),
    0x2F: ("pushdouble", "d"), 0x30: ("pushscope", ""), 0x31: ("pushnamespace", "u"),
    0x32: ("hasnext2", "uu"), 0x40: ("newfunction", "u"), 0x41: ("call", "u"),
    0x42: ("construct", "u"), 0x43: ("callmethod", "uu"), 0x44: ("callstatic", "uu"),
    0x45: ("callsuper", "mu"), 0x46: ("callproperty", "mu"), 0x47: ("returnvoid", ""),
    0x48: ("returnvalue", ""), 0x49: ("constructsuper", "u"), 0x4A: ("constructprop", "mu"),
    0x4C: ("callproplex", "mu"), 0x4E: ("callsupervoid", "mu"), 0x4F: ("callpropvoid", "mu"),
    0x53: ("applytype", "u"), 0x55: ("newobject", "u"), 0x56: ("newarray", "u"),
    0x57: ("newactivation", ""), 0x58: ("newclass", "u"), 0x59: ("getdescendants", "m"),
    0x5A: ("newcatch", "u"), 0x5D: ("findpropstrict", "m"), 0x5E: ("findproperty", "m"),
    0x5F: ("finddef", "m"), 0x60: ("getlex", "m"), 0x61: ("setproperty", "m"),
    0x62: ("getlocal", "u"), 0x63: ("setlocal", "u"), 0x64: ("getglobalscope", ""),
    0x65: ("getscopeobject", "B"), 0x66: ("getproperty", "m"), 0x68: ("initproperty", "m"),
    0x6A: ("deleteproperty", "m"), 0x6C: ("getslot", "u"), 0x6D: ("setslot", "u"),
    0x6E: ("getglobalslot", "u"), 0x6F: ("setglobalslot", "u"), 0x70: ("convert_s", ""),
    0x71: ("esc_xelem", ""), 0x72: ("esc_xattr", ""), 0x73: ("convert_i", ""), 0x74: ("convert_u", ""),
    0x75: ("convert_d", ""), 0x76: ("convert_b", ""), 0x77: ("convert_o", ""), 0x78: ("checkfilter", ""),
    0x80: ("coerce", "m"), 0x81: ("coerce_b", ""), 0x82: ("coerce_a", ""), 0x83: ("coerce_i", ""),
    0x84: ("coerce_d", ""), 0x85: ("coerce_s", ""), 0x86: ("astype", "m"), 0x87: ("astypelate", ""),
    0x88: ("coerce_u", ""), 0x89: ("coerce_o", ""), 0x90: ("negate", ""), 0x91: ("increment", ""),
    0x92: ("inclocal", "u"), 0x93: ("decrement", ""), 0x94: ("declocal", "u"), 0x95: ("typeof", ""),
    0x96: ("not", ""), 0x97: ("bitnot", ""), 0xA0: ("add", ""), 0xA1: ("subtract", ""),
    0xA2: ("multiply", ""), 0xA3: ("divide", ""), 0xA4: ("modulo", ""), 0xA5: ("lshift", ""),
    0xA6: ("rshift", ""), 0xA7: ("urshift", ""), 0xA8: ("bitand", ""), 0xA9: ("bitor", ""),
    0xAA: ("bitxor", ""), 0xAB: ("equals", ""), 0xAC: ("strictequals", ""), 0xAD: ("lessthan", ""),
    0xAE: ("lessequals", ""), 0xAF: ("greaterthan", ""), 0xB0: ("greaterequals", ""),
    0xB1: ("instanceof", ""), 0xB2: ("istype", "m"), 0xB3: ("istypelate", ""), 0xB4: ("in", ""),
    0xC0: ("increment_i", ""), 0xC1: ("decrement_i", ""), 0xC2: ("inclocal_i", "u"),
    0xC3: ("declocal_i", "u"), 0xC4: ("negate_i", ""), 0xC5: ("add_i", ""), 0xC6: ("subtract_i", ""),
    0xC7: ("multiply_i", ""), 0xD0: ("getlocal0", ""), 0xD1: ("getlocal1", ""), 0xD2: ("getlocal2", ""),
    0xD3: ("getlocal3", ""), 0xD4: ("setlocal0", ""), 0xD5: ("setlocal1", ""), 0xD6: ("setlocal2", ""),
    0xD7: ("setlocal3", ""), 0xEF: ("debug", "BuBu"), 0xF0: ("debugline", "u"), 0xF1: ("debugfile", "s"),
}


class R:
    def __init__(self, b, p=0):
        self.b, self.p = b, p

    def u8(self):
        v = self.b[self.p]; self.p += 1; return v

    def u16(self):
        v = struct.unpack_from("<H", self.b, self.p)[0]; self.p += 2; return v

    def s24(self):
        v = self.b[self.p] | (self.b[self.p + 1] << 8) | (self.b[self.p + 2] << 16); self.p += 3
        return v - (1 << 24) if v & 0x800000 else v

    def u30(self):
        r = 0; s = 0
        for _ in range(5):
            x = self.b[self.p]; self.p += 1
            r |= (x & 0x7F) << s
            if not x & 0x80: break
            s += 7
        return r

    def d64(self):
        v = struct.unpack_from("<d", self.b, self.p)[0]; self.p += 8; return v


def swf_abcs(path):
    data = open(path, "rb").read()
    if data[:3] != b"FWS":
        raise SystemExit("only uncompressed FWS supported")
    nbits = data[8] >> 3
    rect_bytes = (5 + 4 * nbits + 7) // 8
    p = 8 + rect_bytes + 4
    out = []
    while p + 2 <= len(data):
        hdr = struct.unpack_from("<H", data, p)[0]; p += 2
        code, ln = hdr >> 6, hdr & 0x3F
        if ln == 0x3F:
            ln = struct.unpack_from("<I", data, p)[0]; p += 4
        body = data[p:p + ln]; p += ln
        if code in (82, 300):  # DoABC2 (Gameloft's gameswf renumbers it to tag 300)
            q = 4
            q = body.index(b"\0", q) + 1
            out.append(body[q:])
        elif code == 72:
            out.append(body)
        if code == 0:
            break
    return out


class ABC:
    def __init__(self, b):
        r = R(b)
        r.u16(); r.u16()
        n = r.u30(); self.ints = [0] + [self._s32(r.u30()) for _ in range(max(0, n - 1))]
        n = r.u30(); self.uints = [0] + [r.u30() for _ in range(max(0, n - 1))]
        n = r.u30(); self.dbls = [0.0] + [r.d64() for _ in range(max(0, n - 1))]
        n = r.u30(); self.strs = [""]
        for _ in range(max(0, n - 1)):
            ln = r.u30(); self.strs.append(b[r.p:r.p + ln].decode("utf-8", "replace")); r.p += ln
        n = r.u30(); self.ns = [(0, 0)]
        for _ in range(max(0, n - 1)):
            k = r.u8(); self.ns.append((k, r.u30()))
        n = r.u30(); self.nss = [[]]
        for _ in range(max(0, n - 1)):
            c = r.u30(); self.nss.append([r.u30() for _ in range(c)])
        n = r.u30(); self.mn = [None]
        for _ in range(max(0, n - 1)):
            k = r.u8()
            if k in (0x07, 0x0D): self.mn.append(("Q", r.u30(), r.u30()))
            elif k in (0x0F, 0x10): self.mn.append(("RTQ", r.u30()))
            elif k in (0x11, 0x12): self.mn.append(("RTQL",))
            elif k in (0x09, 0x0E): self.mn.append(("M", r.u30(), r.u30()))
            elif k in (0x1B, 0x1C): self.mn.append(("ML", r.u30()))
            elif k == 0x1D:
                base = r.u30(); c = r.u30(); self.mn.append(("TN", base, [r.u30() for _ in range(c)]))
            else: raise ValueError(f"multiname kind {k:#x}")
        n = r.u30(); self.methods = []
        for _ in range(n):
            pc = r.u30(); ret = r.u30(); pt = [r.u30() for _ in range(pc)]
            name = r.u30(); flags = r.u8()
            if flags & 0x08:
                oc = r.u30()
                for _ in range(oc): r.u30(); r.u8()
            if flags & 0x80:
                for _ in range(pc): r.u30()
            self.methods.append({"name": name, "params": pc})
        n = r.u30()
        for _ in range(n):
            r.u30(); ic = r.u30()
            for _ in range(ic): r.u30(); r.u30()
        n = r.u30(); self.inst = []
        for _ in range(n):
            name = r.u30(); sup = r.u30(); flags = r.u8()
            if flags & 0x08: r.u30()
            ic = r.u30(); [r.u30() for _ in range(ic)]
            iinit = r.u30(); traits = self._traits(r)
            self.inst.append({"name": name, "iinit": iinit, "traits": traits})
        self.cls = []
        for _ in range(n):
            cinit = r.u30(); self.cls.append({"cinit": cinit, "traits": self._traits(r)})
        n = r.u30(); self.scripts = []
        for _ in range(n):
            init = r.u30(); self.scripts.append({"init": init, "traits": self._traits(r)})
        n = r.u30(); self.bodies = {}
        for _ in range(n):
            m = r.u30(); r.u30(); r.u30(); r.u30(); r.u30()
            cl = r.u30(); code = b[r.p:r.p + cl]; r.p += cl
            ec = r.u30()
            for _ in range(ec): r.u30(); r.u30(); r.u30(); r.u30(); r.u30()
            self._traits(r)
            self.bodies[m] = code
        # method -> owner name
        self.owner = {}
        for i, ins in enumerate(self.inst):
            cn = self.mname(ins["name"])
            self.owner[ins["iinit"]] = f"{cn}.<init>"
            self.owner[self.cls[i]["cinit"]] = f"{cn}.<cinit>"
            for t in ins["traits"]:
                if t[1] is not None: self.owner[t[1]] = f"{cn}.{self.mname(t[0])}{t[2]}"
            for t in self.cls[i]["traits"]:
                if t[1] is not None: self.owner[t[1]] = f"{cn}.static {self.mname(t[0])}{t[2]}"

    @staticmethod
    def _s32(v):
        return v - (1 << 32) if v & 0x80000000 else v

    def _traits(self, r):
        out = []
        for _ in range(r.u30()):
            name = r.u30(); kb = r.u8(); kind = kb & 0x0F; meth = None; tag = ""
            if kind in (0, 6):
                r.u30(); r.u30(); vi = r.u30()
                if vi: r.u8()
            elif kind in (1, 2, 3):
                r.u30(); meth = r.u30(); tag = {1: "()", 2: " get", 3: " set"}[kind]
            elif kind == 4:
                r.u30(); r.u30()
            elif kind == 5:
                r.u30(); meth = r.u30(); tag = "()"
            if kb & 0x40:
                for _ in range(r.u30()): r.u30()
            out.append((name, meth, tag))
        return out

    def mname(self, i):
        if i <= 0 or i >= len(self.mn) or self.mn[i] is None: return f"mn{i}"
        m = self.mn[i]
        if m[0] == "Q": return self.strs[m[2]] if m[2] else "*"
        if m[0] in ("M", "RTQ"): return self.strs[m[1]] if m[1] else "*"
        if m[0] == "TN": return f"{self.mname(m[1])}.<{','.join(self.mname(x) for x in m[2])}>"
        return f"[{m[0]}]"

    def dis(self, mi):
        code = self.bodies.get(mi)
        if code is None: return [f"(no body for method {mi})"]
        r = R(code); out = []
        while r.p < len(code):
            at = r.p; op = r.u8()
            name, kinds = OPS.get(op, (f"op_{op:#04x}", ""))
            args = []
            if kinds == "L":
                base = at; d = r.s24(); c = r.u30(); cs = [r.s24() for _ in range(c + 1)]
                args = [f"default->{base + d}", "cases->" + ",".join(str(base + x) for x in cs)]
            else:
                for k in kinds:
                    if k == "u": args.append(str(r.u30()))
                    elif k == "m": args.append(self.mname(r.u30()))
                    elif k == "s": i = r.u30(); args.append(repr(self.strs[i] if i < len(self.strs) else i))
                    elif k == "i": i = r.u30(); args.append(str(self.ints[i] if i < len(self.ints) else i))
                    elif k == "U": i = r.u30(); args.append(str(self.uints[i] if i < len(self.uints) else i))
                    elif k == "d": i = r.u30(); args.append(str(self.dbls[i] if i < len(self.dbls) else i))
                    elif k == "j": d = r.s24(); args.append(f"->{r.p + d}")
                    elif k == "b": v = r.u8(); args.append(str(v - 256 if v > 127 else v))
                    elif k == "B": args.append(str(r.u8()))
            out.append(f"{at:5d}  {name} {' '.join(args)}")
        return out

    def refs(self, mi):
        """set of strings/names referenced by a method body (pushstring + multinames)."""
        code = self.bodies.get(mi, b""); r = R(code); s = set()
        while r.p < len(code):
            at = r.p; op = r.u8(); name, kinds = OPS.get(op, ("?", ""))
            if kinds == "L":
                r.s24(); c = r.u30(); [r.s24() for _ in range(c + 1)]; continue
            for k in kinds:
                if k == "u": r.u30()
                elif k == "m": s.add(self.mname(r.u30()))
                elif k == "s": i = r.u30(); s.add(self.strs[i] if i < len(self.strs) else "")
                elif k in "iUd": r.u30()
                elif k == "j": r.s24()
                elif k in "bB": r.u8()
        return s


class ABCLoose(ABC):
    """Constant pool parsed normally; method bodies located by anchor scan.

    Gameloft's gameswf post-processes the method_info / method_body tables (the standard
    layout does not parse past the constant pool), but every body still carries the
    standard header [method u30][max_stack][locals][init_scope][max_scope][code_len]
    followed by code that almost always starts with getlocal0;pushscope (d0 30). We find
    bodies by that anchor; owner names are unavailable, so methods are keyed by the
    method index stored in the body header.
    """

    def __init__(self, b):
        r = R(b)
        r.u16(); r.u16()
        n = r.u30(); self.ints = [0] + [self._s32(r.u30()) for _ in range(max(0, n - 1))]
        n = r.u30(); self.uints = [0] + [r.u30() for _ in range(max(0, n - 1))]
        n = r.u30(); self.dbls = [0.0] + [r.d64() for _ in range(max(0, n - 1))]
        n = r.u30(); self.strs = [""]
        for _ in range(max(0, n - 1)):
            ln = r.u30(); self.strs.append(b[r.p:r.p + ln].decode("utf-8", "replace")); r.p += ln
        n = r.u30(); self.ns = [(0, 0)] + [(r.u8(), r.u30()) for _ in range(max(0, n - 1))]
        n = r.u30(); self.nss = [[]]
        for _ in range(max(0, n - 1)):
            c = r.u30(); self.nss.append([r.u30() for _ in range(c)])
        n = r.u30(); self.mn = [None]
        for _ in range(max(0, n - 1)):
            k = r.u8()
            if k in (0x07, 0x0D): self.mn.append(("Q", r.u30(), r.u30()))
            elif k in (0x0F, 0x10): self.mn.append(("RTQ", r.u30()))
            elif k in (0x11, 0x12): self.mn.append(("RTQL",))
            elif k in (0x09, 0x0E): self.mn.append(("M", r.u30(), r.u30()))
            elif k in (0x1B, 0x1C): self.mn.append(("ML", r.u30()))
            elif k == 0x1D:
                base = r.u30(); c = r.u30(); self.mn.append(("TN", base, [r.u30() for _ in range(c)]))
            else: raise ValueError(f"multiname kind {k:#x}")
        self.bodies = {}; self.body_at = {}; self.owner = {}
        for m in re.finditer(rb"\xd0\x30", b):
            c = m.start()
            for back in range(6, 31):
                p = c - back
                if p < 0: continue
                q = R(b, p)
                try:
                    mi = q.u30(); ms = q.u30(); lc = q.u30(); isd = q.u30(); msd = q.u30(); cl = q.u30()
                except IndexError:
                    continue
                if q.p == c and 0 < cl < 400000 and ms < 1000 and lc < 1000 and isd <= msd < 200:
                    # key by code position: the header's method-index field is not reliable
                    self.bodies[c] = b[c:c + cl]; self.body_at[c] = c
                    break


def main():
    path, cmd, arg = sys.argv[1], sys.argv[2], sys.argv[3]
    for ai, b in enumerate(swf_abcs(path)):
        try:
            a = ABC(b)
        except Exception:
            a = ABCLoose(b)
        if cmd == "strings":
            for s in a.strs:
                if re.search(arg, s): print(f"abc{ai}: {s}")
        elif cmd == "uses":
            rx = re.compile(arg)
            for mi in sorted(a.bodies):
                hit = sorted(x for x in a.refs(mi) if rx.search(x))
                if hit: print(f"abc{ai} m{mi} {a.owner.get(mi, '?')}: {hit}")
        elif cmd == "dis":
            mi = int(arg)
            if mi in a.bodies:
                print(f"abc{ai} m{mi} {a.owner.get(mi, '?')}")
                print("\n".join(a.dis(mi)))


if __name__ == "__main__":
    main()
