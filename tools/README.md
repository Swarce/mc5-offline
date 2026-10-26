# Analysis tools

Everything here runs on the player's own files and stores no game code or data. Ghidra addresses are ELF addresses
+ 0x100000 (the image base Ghidra picks for `libMC5.so`).

| Tool | What it does |
|---|---|
| `ghidra/ExportAll.java` | Headless Ghidra post-script: `functions.tsv`, `calls.tsv`, `strings.tsv` (string → referencing functions) and a parallel decompilation of every function into `decomp/XXXX.c` |
| `ghidra/Query.java` | On-demand `decomp`, `callers` or `refs` for a list of addresses |
| `ghidra/DecompLong.java` | Decompiles functions that time out in the bulk export (for example the in-match dispatcher at G:0xbe5fd8) |
| `re/objstr.py` | Decodes the strings the binary builds one character at a time in static initialisers (`objstrings.tsv`) |
| `re/xref.py`, `re/calls.py`, `re/dis.py`, `re/rangestr.py` | Fast ARM64 helpers without Ghidra: string xrefs (ADRP+ADD/LDR), BL callers, annotated disassembly, strings used in an address range (ELF addresses) |
| `protocol-catalog/catalog.py` | Generates [docs/protocol/tcp-messages.md](../docs/protocol/tcp-messages.md) |
| `protocol-catalog/federation.py` | Generates [docs/protocol/federation-requests.md](../docs/protocol/federation-requests.md) |

Typical run (Ghidra 11.2.1, ~9 GB heap, about 35 minutes of analysis plus 15 minutes of decompilation for 96k
functions):

```sh
analyzeHeadless <proj_dir> mc5 -import <split_config.arm64_v8a>/lib/arm64-v8a/libMC5.so -max-cpu 4 \
  -scriptPath tools/ghidra -postScript ExportAll.java <export_dir> 3
python3 -I tools/re/objstr.py <export_dir>/decomp > <export_dir>/objstrings.tsv
analyzeHeadless <proj_dir> mc5 -process libMC5.so -noanalysis -readOnly -scriptPath tools/ghidra \
  -postScript DecompLong.java <export_dir>/dispatch_be5fd8.c 1200 0x00be5fd8
python3 -I tools/protocol-catalog/catalog.py <export_dir> <export_dir>/dispatch_be5fd8.c > docs/protocol/tcp-messages.md
```
