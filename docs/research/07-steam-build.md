# 07 — The Steam (Windows) build as a research aid

The shut-down Steam release ships `mc5.exe`, `mc5.iobj` and `mc5.ipdb` next to each
other. The player provided copies for local analysis. **They are Gameloft files: none
of them, and nothing extracted from them in bulk, goes into this repository.** This
note records only what they contain and how useful they are.

## What the files are

| File | What it is | Useful? |
|------|------------|---------|
| `mc5.exe` | PE32 i386, linked 2021-05-19, image base 0x400000, 24.7 MB. It statically contains the whole game (GameMpManager, CAIMpManager, the menus, Vivox, Bullet, gameswf, curl). Its debug directory points to `D:\MC5_BuildMachine\MC5_Windows\trunk\game\build\_Resources_Steam\mc5.pdb`, and **that PDB is not shipped**. | Some |
| `mc5.iobj` | The MSVC *incremental LTCG* object database (`/LTCG:incremental`). It only holds the objects that changed in the last incremental link. Its 6144 COFF symbols (1837 unique names) cover just the Windows platform layer: WCPToolkit input/event/gamepad managers, glf, `EntryPoint`, `UtilsWindows`, subtitles, the Steam API wrappers and `CLimitSingleInstance`. | No |
| `mc5.ipdb` | The matching incremental-LTCG *PDB database*: a link-time cache, not an MSF debug PDB (`llvm-pdbutil` rejects it). About 295 readable strings, all decorated names from the same platform layer. | No |

So the `.iobj`/`.ipdb` pair is a linker cache that a release build left behind. It
carries **no symbols for the game core**: no CAIMpManager, GameMpManager, connection
class or QPM.

## What the exe adds over libMC5.so

- **RTTI.** Only 604 `.?AV`/`.?AU` type descriptors, almost all third-party (Vivox,
  Bullet, gameswf, std). The game core is built without RTTI, as on Android.
- **Profiling and log names the Android build strips.** There are about 10 game
  `Class::Method` strings, for example `CAIMpManager::UpdateBotPlayers`,
  `GameMpManager::OnNewPlayerConnected`, `GameMpManager::OnHandleAllMessages`,
  `GameMpManager::RequestAgainSnapshot`,
  `MPGSLobbyManager::CheckAndHandleConnectivity` and `GS_EndMultiplayer::Update1`.
  They confirm class names for functions we had already found on arm64:
  - UpdateBotPlayers is 0xb41a80.
  - OnNewPlayerConnected is 0xae3ba0.
  - The owner of bm = MP+0xb340 is **CAIMpManager**.
  - The owner of MP is **GameMpManager**.
- **Config keys.** The exe has the same `_automatch_name=quickplay*`,
  `lobby_host`/`lobby_tcp_port` and `_br_lobby_*` keys as Android. Nothing new.
- About 46k strings appear only in the exe. Almost all of them come from the Windows
  libraries it links (curl/OpenSSL, the MSVC runtime, boost type names).

## Verdict

These files are a weak cross-reference, not a symbol source. They put names on a
handful of functions we already know, and they don't unblock the bot join (the host's
connection object has a single peer slot; see 06 §C2). If the x86 code is ever needed, for example to
compare a function's logic with a second compiler's output, anchor it on one of the
`Class::Method` strings above. Keep the binaries outside the repo.
