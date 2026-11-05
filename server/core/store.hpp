// store.hpp — crash-safe small-file persistence for the offline server's JSON files.
//
// save_atomic(path, text): write path.tmp, fsync it, keep the previous good copy as
// path.bak, then rename path.tmp over path (rename is atomic on one filesystem).
// load_json(path): try path, then path.bak; a file that exists but does not parse is
// moved aside to path.broken-<epoch> (never silently overwritten), so a bad write or
// a hand edit can always be recovered from the phone. C++17, POSIX, header-only.
#pragma once

#include <cerrno>
#include <cstdio>
#include <ctime>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json.hpp"
#include "log.hpp"

namespace mc5 {
namespace store {

inline bool read_file(const std::string& path, std::string& out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    out.clear();
    char buf[8192];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        out.append(buf, n);
        if (out.size() > (16u << 20)) { std::fclose(f); return false; } // 16 MB sanity cap
    }
    std::fclose(f);
    return true;
}

inline bool exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

inline bool mkdirs(const std::string& dir) {
    if (dir.empty()) return false;
    std::string cur;
    for (std::size_t i = 0; i < dir.size(); ++i) {
        cur.push_back(dir[i]);
        if ((dir[i] == '/' && i > 0) || i + 1 == dir.size()) ::mkdir(cur.c_str(), 0775);
    }
    struct stat st;
    return ::stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

inline bool save_atomic(const std::string& path, const std::string& text) {
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0664);
    if (fd < 0) { logw("[store] open %s failed (errno %d)", tmp.c_str(), errno); return false; }
    std::size_t off = 0;
    while (off < text.size()) {
        ssize_t w = ::write(fd, text.data() + off, text.size() - off);
        if (w < 0) { if (errno == EINTR) continue; ::close(fd); logw("[store] write %s failed", tmp.c_str()); return false; }
        off += static_cast<std::size_t>(w);
    }
    ::fsync(fd);
    ::close(fd);
    if (exists(path)) ::rename(path.c_str(), (path + ".bak").c_str());
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        logw("[store] rename %s failed (errno %d)", path.c_str(), errno);
        return false;
    }
    return true;
}

// Loads a JSON object from path (or path.bak). Returns false if neither exists or
// parses to an object; `found` tells whether anything was on disk at all.
inline bool load_json(const std::string& path, Json& out, bool* found = nullptr) {
    if (found) *found = false;
    const std::string cands[2] = {path, path + ".bak"};
    for (const std::string& p : cands) {
        std::string text;
        if (!read_file(p, text)) continue;
        if (found) *found = true;
        Json j;
        if (Json::try_parse(text, j) && j.is_object()) {
            if (&p != &cands[0]) logw("[store] %s unreadable; recovered from %s", path.c_str(), p.c_str());
            out = j;
            return true;
        }
        std::string aside = p + ".broken-" + std::to_string(static_cast<long long>(std::time(nullptr)));
        ::rename(p.c_str(), aside.c_str());
        loge("[store] %s does not parse as a JSON object; moved to %s", p.c_str(), aside.c_str());
    }
    return false;
}

} // namespace store
} // namespace mc5
