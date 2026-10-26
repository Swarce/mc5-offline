# Roadmap

Done items are struck through. Details and evidence: [research/00-recon.md](research/00-recon.md) §7.

## Done

- ~~Phase 0: backup checklist ([BACKUP.md](BACKUP.md))~~
- ~~Phase 1: recon of engine, online stack, multiplayer transport, content delivery, protections~~
- ~~Phase 1b: offline flags, profile and save, meta channel (TS), Federation request builders, match authority and bots ([research/01-phase1b.md](research/01-phase1b.md), [protocol/](protocol/))~~

## Next

| Milestone | Content |
|---|---|
| M0 | Embedded `libmc5offline.so` with diagnostics and hooks; patcher (split merge, local asset packs, library load); Federation boot |
| M1 | Offline campaign: the TS (`ClientSendInitSettings`, profile document owned and stored on the device, config, the campaign's client requests with responses from the game's own tables), BALD from local files. Needs the asset-pack backup |
| M2 | Bot or solo matches: Anubis lobby/controller, a GS that relays and runs the room lifecycle; the local client holds the authority role and runs the bots. First task: find how the role is assigned |
| M3 | LAN: one phone hosts, others join |
| M4 | Internet: desktop/VPS server build, cross-device accounts, optional relay |
