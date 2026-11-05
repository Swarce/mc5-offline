// Diagnostics for the embedded library (M0.5).
//
// Everything important goes to logcat under the "MC5Offline" tag, because the
// owner's file uploads from the phone often arrive empty while logcat is
// reliable; a copy is also mirrored to a file under the app data dir when known.
//
//  * boot trace      — timestamped milestones from library load to hooks installed
//  * crash reporter  — native signal handlers dump the faulting frame + a
//                       module+offset backtrace, then chain to the platform handler
//  * watchdog        — a heartbeat thread, and an on-demand thread-state dump
//
// C++17.
#pragma once

#include <string>
#include <vector>

namespace mc5 {
namespace diag {

// One-time setup: open the log-file copy under data_dir (if non-empty), install
// the crash handler, start the watchdog, and mark the boot-trace epoch. Safe to
// call more than once; only the first call takes effect.
void init(const std::string& data_dir);

// The directory init() chose for the log copy ("" if none): the app's external files
// dir when writable, else its internal files dir. The save lives under it.
std::string data_dir();

// Timestamped "[boot +Nms] <stage>" marker (monotonic from the first init()).
void boot_trace(const char* stage);

// Delete the individual files an earlier offline build wrote into <files>/bald/ (the
// empty "<dlc/>" map and a toc/hashes naming only "..._map_android_dlc_1"). Never a
// directory and never any other file, since the player's real DLC lives there too.
void remove_offline_bald_cache();
// Same over explicit directories (host-testable). Returns the number of files removed.
int remove_offline_bald_cache_in(const std::vector<std::string>& dirs);

// List every thread (tid, name, scheduler state) to the log. Not for use from a
// signal handler — call it from normal context (startup, watchdog, on request).
void dump_threads(const char* reason);

} // namespace diag
} // namespace mc5
