// bald_mirror.hpp — answer Gameloft's runtime-DLC manager (BALD) from the player's OWN
// restored DLC folder (<files>/bald), so the campaign zones and MP maps they backed up
// before the shutdown load offline. Nothing is shipped and nothing in that folder is
// ever written, renamed or deleted by us.
//
// How BALD uses a complete local folder (libMC5 6.0.12a; docs/research/05-bald.md):
// state 1 GETs bald_<n>___index, byte-compares the reply body with the local
// bald___index___.txt, checks bald___version___.txt == "6.0.12a", parses the local toc
// and hashes, accepts each toc asset whose file exists (no md5, no size check) and is
// ready (state 3). No toc request and no download follow. So the ONLY reply we give is
// the exact bytes of the player's own index file, and only after a preflight proves
// every condition that would otherwise send BALD to state 2 (which downloads a toc and
// ERASES every local asset missing from it) or crash the DLC wrapper.
//
// Toc requests are never answered (state 2 is the deleting path). Asset payload
// requests are never answered either (a mismatched body is deleted after post-check).
// C++17.
#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace mc5 {

struct BaldPreflight {
    bool ok = false;             // serve the index?
    std::string dir;             // resolved folder (with trailing '/')
    std::string index_bytes;     // verbatim contents of bald___index___.txt
    std::vector<std::string> fails;  // hard-gate failures (H1..H10)
    std::vector<std::string> notes;  // soft findings (missing files, locations, ...)
    std::size_t assets = 0, present = 0;
    long long bytes_total = 0, bytes_missing = 0;
    std::vector<std::string> locations; // map locations, for the log
};

class BaldMirror {
public:
    // Candidate folders, first existing one with a bald___index___.txt wins.
    void set_dirs(std::vector<std::string> dirs);
    // Preflight for variant n ("android_astc_h", ...). Cached per variant and process.
    BaldPreflight preflight(const std::string& n, bool require_sizes = true);
    // Uncached core (tests).
    static BaldPreflight run(const std::vector<std::string>& dirs, const std::string& n, bool require_sizes);

private:
    std::mutex mu_;
    std::vector<std::string> dirs_;
    std::map<std::string, BaldPreflight> cache_;
};

// True if a small file's content is something an earlier offline build wrote into
// <files>/bald (the empty "<dlc/>" map, or a toc/hashes naming only
// "..._map_android_dlc_1"). Used by the boot sweep, which deletes only such files.
bool bald_is_offline_marker(const std::string& content);

} // namespace mc5
