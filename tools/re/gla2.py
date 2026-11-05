"""Reader for Gameloft .gla2 asset archives (MC5 6.0.12a), reimplemented from libMC5:
archive open 0x87c308, cipher 0xbbd2b0 (PRNG 0xbbd278), seed 0x3857a.

Layout: 16-byte header, encrypted with the cipher, holding big-endian u32s
{0, dir_offset, entry_count, magic 0xa9d10201}. The directory at dir_offset is plain:
22-byte records {u64 name-hash, be32 offset, be32 size, be32 packed_size, be16 flags}
(flags bit 2 -> 6 extra bytes; not seen in ui/strings). Entry data: flags & 1 ->
encrypted with the same cipher/seed; flags & 8 -> LZ4 blocks (ui.gla2 SWFs).

strings.gla2: one entry per language pack; a pack is NUL-separated UTF-8 strings whose
ordinal is the native string id used by GetString 0x8eec38 / 0x841f38 (e.g. 1733 =
"Failed to connect! ...", 1942 = "Servers are temporarily overloaded ...").

Usage:
  python3 -I gla2.py list    <file.gla2>
  python3 -I gla2.py extract <file.gla2> <outdir>          (decrypts flag-1 entries)
  python3 -I gla2.py strfind <strings.gla2> <regex>         (id + text, all packs)
  python3 -I gla2.py strid   <strings.gla2> <id> [<id>...]  (text in the English pack)
"""
import os, re, struct, sys

SEED = 0x3857A
MAGIC = 0xA9D10201


class _Rand:
    def __init__(self, seed): self.s = seed & 0xFFFFFFFF

    def __call__(self, n):
        self.s = (self.s * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        v = self.s >> 16
        return v % n if n else v


def _rotr(v, r, bits):
    m = (1 << bits) - 1
    r %= bits
    v &= m
    return ((v >> r) | (v << (bits - r))) & m


def decrypt(buf, seed=SEED):
    rnd = _Rand(seed)
    out = bytearray(len(buf))
    n = len(buf)
    i = 0
    while i + 4 <= n:
        w = struct.unpack_from("<I", buf, i)[0]
        d = rnd(2); r = rnd(32)
        w = _rotr(w, r, 32) if d else _rotr(w, (32 - r) % 32, 32)
        k = (rnd(256) << 24) | (rnd(256) << 16) | (rnd(256) << 8) | rnd(256)
        struct.pack_into("<I", out, i, (k ^ w) & 0xFFFFFFFF)
        i += 4
    rem = n - i
    d = rnd(2)
    if rem:
        bits = rem * 8
        v = int.from_bytes(buf[i:], "little")
        r = rnd(bits)
        v = _rotr(v, r, bits) if d else _rotr(v, (bits - r) % bits, bits)
        k = 0
        for _ in range(rem): k = (k << 8) | rnd(256)
        out[i:] = ((k ^ v) & ((1 << bits) - 1)).to_bytes(rem, "little")
    return bytes(out)


def read_dir(data):
    _, dir_off, count, magic = struct.unpack(">4I", decrypt(data[:16]))
    if magic != MAGIC: raise ValueError(f"bad gla2 magic 0x{magic:08x}")
    recs = []
    p = dir_off
    for _ in range(count):
        h = data[p:p + 8].hex()
        off, size, packed, fl = struct.unpack(">IIIH", data[p + 8:p + 22])
        p += 22 + (6 if fl & 4 else 0)
        recs.append((h, off, size, packed, fl))
    return recs


def entry_bytes(data, rec):
    h, off, size, packed, fl = rec
    if fl & 8: raise NotImplementedError("LZ4-packed entry (see scratch lz4 walker)")
    raw = data[off:off + size]
    return decrypt(raw) if fl & 1 else raw


def string_packs(data):
    """Yield (hash, [strings]) for each decrypted text pack (heuristic: many NULs, UTF-8)."""
    for rec in read_dir(data):
        if not rec[4] & 1 or rec[2] < 1024: continue
        b = entry_bytes(data, rec)
        parts = b.split(b"\0")
        if len(parts) < 100: continue
        yield rec[0], [s.decode("utf-8", "replace") for s in parts]


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    data = open(path, "rb").read()
    if cmd == "list":
        for h, off, size, packed, fl in read_dir(data):
            print(f"{h} off=0x{off:x} size={size} packed={packed} flags={fl}")
    elif cmd == "extract":
        od = sys.argv[3]
        os.makedirs(od, exist_ok=True)
        for rec in read_dir(data):
            if rec[4] & 8: continue
            open(os.path.join(od, f"{rec[0]}.bin"), "wb").write(entry_bytes(data, rec))
    elif cmd == "strfind":
        rx = re.compile(sys.argv[3])
        for h, strs in string_packs(data):
            for i, s in enumerate(strs):
                if rx.search(s): print(f"{h} id={i} (0x{i:x}): {s[:160]!r}")
    elif cmd == "strid":
        ids = [int(x, 0) for x in sys.argv[3:]]
        for h, strs in string_packs(data):
            if any("Failed to connect!" in s for s in strs):  # the English pack
                for i in ids: print(f"id={i} (0x{i:x}): {strs[i]!r}" if i < len(strs) else f"id={i}: out of range")
                return
        print("English pack not found")


if __name__ == "__main__":
    main()
