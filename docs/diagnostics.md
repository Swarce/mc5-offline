# Diagnostics (M0.5)

Everything important is logged to **logcat** under the tag `MC5Offline`, because
the owner's file uploads from the phone often arrive as 0 bytes while logcat text
is reliable. A copy is also mirrored to a file the owner can `adb pull`.

```
adb logcat -s MC5Offline:V
```

Code: `hosts/embedded/diag.{hpp,cpp}`, wired from `bootstrap.cpp` and
`redirect.cpp`; the log core is `server/core/log.hpp`. Installed at the earliest
moment (`JNI_OnLoad`), before the server and hooks, so a crash during startup is
still reported. Host-tested in `tests/test_diag.cpp` (the crash path is portable
Linux and runs under `ctest`).

## Boot trace

Timestamped milestones, monotonic from library load:

```
[boot +0ms]   JNI_OnLoad
[boot +1ms]   diagnostics ready (crash handler + watchdog)
[boot +2ms]   server starting
[boot +6ms]   server started
[boot +812ms] libMC5.so loaded
[boot +813ms] libMC5 http patches applied
[boot +814ms] GOT hooks installed
```

If `libMC5.so NOT seen within timeout` appears, the game never loaded its native
library within 60s and the redirect patches/hooks were not applied.

## Native crash reporter

Signal handlers for `SIGSEGV`, `SIGABRT`, `SIGBUS`, `SIGILL`, `SIGFPE`, on a
dedicated `sigaltstack` (so stack-overflow crashes still report). On a fault it
writes, with async-signal-safe raw writes (no malloc/stdio/locks):

```
*** MC5Offline native crash: SIGSEGV (11) code=1 addr=0x0 tid=4312
  #0  pc=0x7bd4c3a9a0  +0x2a39a0  /data/app/.../lib/arm64/libMC5.so
  #1  ...
*** end backtrace (offsets are module-relative: ELF vaddr = offset) ***
```

Each frame is `pc`, the **module-relative offset**, and the module path. The
offset is the ELF virtual address, resolved by scanning `/proc/self/maps` in the
handler (no `dladdr`). So a libMC5 frame maps straight to the disassembly:

* **ELF vaddr = the printed offset**
* **Ghidra address = offset + 0x100000** (this project's convention)

After dumping, the handler restores the previous handler for that signal and
re-raises, so the platform tombstone (and Crashlytics, if present) still runs —
we add context, we don't swallow the crash.

## Watchdog

A background thread logs a heartbeat every 15s and a full thread-state snapshot
every ~2 minutes:

```
[watchdog] uptime=15s threads=37
[threads] dump (watchdog periodic):
  tid=4312 state=R main
  tid=4319 state=S MC5Offline-srv
  ...
```

`state` is the scheduler state from `/proc/self/task/<tid>/stat` (R running,
S sleeping, D uninterruptible). A game thread stuck in `D`/`R` across several
snapshots while the UI is frozen points at where it is wedged. `dump_threads()`
is also called once right after the server starts.

## Phone-readable log copy

The log is mirrored to `mc5offline.log` at the first writable location:

1. a data dir passed to `init()`, else
2. `/sdcard/Android/data/com.gameloft.android.ANMP.GloftM5HM/files/` — pullable
   with `adb pull` on a non-rooted device, else
3. `/data/data/com.gameloft.android.ANMP.GloftM5HM/files/` (needs root to pull).

The chosen path is logged at startup (`[diag] log copy: … (adb pull this)`).
Logcat remains the primary channel; the file is a convenience backup.
