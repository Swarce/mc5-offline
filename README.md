# MC5 Offline

A preservation project for **Modern Combat 5** (Gameloft, Android 6.0.12a, `com.gameloft.android.ANMP.GloftM5HM`):
keep the campaign and multiplayer playable after Gameloft's online services shut down, with a reimplemented backend
and game server embedded in the game process. Sister project: [MCVS Offline](https://github.com/Swarce/mcvs-offline).

**Status: M2.**
* **Single player boots offline on a real phone:** login, age gate, tutorial and campaign.
* **Just built, not yet device-tested:** the player save, the mission-end screen, and MCVS-style unlock codes
  ([docs/ECONOMY.md](docs/ECONOMY.md)).

See [docs/STATUS.md](docs/STATUS.md).

- [docs/BACKUP.md](docs/BACKUP.md): what every player must back up before the shutdown (the game data is in Play Asset
  Delivery packs that cannot be copied off a phone without root).
- [docs/research/00-recon.md](docs/research/00-recon.md): engine, online stack, multiplayer architecture, content
  delivery, the proposed architecture and milestones.
- [docs/STATUS.md](docs/STATUS.md), [docs/ROADMAP.md](docs/ROADMAP.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Legal note

This repository contains no Gameloft files: no APK, no libraries, no decompiled code and no game data. The patcher
will work on the player's own files on the player's machine. Modern Combat 5 and all related names are trademarks of
Gameloft; this is an unofficial, non-commercial preservation project with no affiliation to Gameloft.
