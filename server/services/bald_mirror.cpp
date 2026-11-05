// bald_mirror.cpp — see bald_mirror.hpp. Gate numbers H1..H10 follow
// docs/research/05-bald.md §3.
#include "bald_mirror.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>

#include <sys/stat.h>
#include <sys/statvfs.h>

#include "../core/json.hpp"
#include "../core/log.hpp"
#include "../core/store.hpp"

namespace mc5 {

namespace {

const char* kVersion = "6.0.12a"; // snprintf("%d.%d.%d%s",6,0,12,"a") in G:0x5f7a88

bool file_size(const std::string& p, long long& sz) {
    struct stat st;
    if (::stat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    sz = static_cast<long long>(st.st_size);
    return true;
}

// The BALD lookup key of an asset name (G:0x136feb0): strip "bald_<n>_" and the
// trailing "_<rev>".
std::string toc_key(const std::string& name, const std::string& prefix) {
    std::size_t r = name.rfind('_');
    if (name.compare(0, prefix.size(), prefix) != 0 || r == std::string::npos || r <= prefix.size()) return std::string();
    return name.substr(prefix.size(), r - prefix.size());
}

// How the wrapper names a pack: lower(P + ".gla2") with '.' -> '_' (G:0x136e010).
std::string pack_key(const std::string& p) {
    std::string k = p + ".gla2";
    for (char& c : k) { c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); if (c == '.') c = '_'; }
    return k;
}

// A minimal tag scanner for the DLC map (pugixml XML read by G:0xcbcec0): root <dlc>,
// children of <mandatory> are packs, children of <locations> are locations whose
// children are packs. Element names below those levels are not checked by the game.
struct MapScan {
    bool ok = false;
    std::string err, root;
    std::vector<std::string> mandatory;
    std::vector<std::pair<std::string, std::vector<std::string>>> locations;
};

std::string decode_entities(const std::string& raw) {
    std::string out;
    static const std::pair<const char*, char> ents[] = {{"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}};
    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] != '&') { out.push_back(raw[i]); continue; }
        bool hit = false;
        for (const auto& en : ents)
            if (raw.compare(i, std::strlen(en.first), en.first) == 0) { out.push_back(en.second); i += std::strlen(en.first) - 1; hit = true; break; }
        if (!hit) out.push_back('&');
    }
    return out;
}

// Attributes of a start tag body (after the element name): name="v" / name='v' pairs,
// tokenised in order so a 'name=' inside another attribute's value is never read.
// Returns false on malformed syntax.
bool attrs(const std::string& tag, std::size_t from, std::map<std::string, std::string>& out) {
    std::size_t i = from, n = tag.size();
    while (i < n) {
        while (i < n && std::isspace(static_cast<unsigned char>(tag[i]))) ++i;
        if (i >= n || tag[i] == '/') break;
        std::size_t k = i;
        while (i < n && tag[i] != '=' && !std::isspace(static_cast<unsigned char>(tag[i])) && tag[i] != '/') ++i;
        std::string key = tag.substr(k, i - k);
        while (i < n && std::isspace(static_cast<unsigned char>(tag[i]))) ++i;
        if (key.empty() || i >= n || tag[i] != '=') return false;
        ++i;
        while (i < n && std::isspace(static_cast<unsigned char>(tag[i]))) ++i;
        if (i >= n || (tag[i] != '"' && tag[i] != '\'')) return false;
        char q = tag[i++];
        std::size_t e = tag.find(q, i);
        if (e == std::string::npos) return false;
        if (!out.count(key)) out[key] = decode_entities(tag.substr(i, e - i)); // first wins, as pugixml attribute()
        i = e + 1;
    }
    return true;
}

// Mirrors G:0xc62430: doc.child("dlc") -> child("mandatory") / child("locations") (the
// FIRST element of each name, 0xbbc728), then first_child/next_sibling over ALL node
// types (0xbbc8d8/0xbbc840). pugixml parse options 0x74 keep non-whitespace text and
// CDATA as nodes, and each such node would become a nameless pack -> NULL handle ->
// SIGSEGV at 0x8e1728. So: any text/CDATA inside the first <mandatory> or a location of
// the first <locations> fails; a second <dlc>/<mandatory>/<locations> fails (ambiguous).
MapScan scan_map(const std::string& x) {
    MapScan m;
    struct Frame { std::string el; int role; }; // role: 0 other, 1 dlc, 2 mandatory, 3 locations, 4 location
    std::vector<Frame> st;
    int n_dlc = 0, n_mand = 0, n_locs = 0, cur_loc = -1;
    std::size_t i = 0;
    auto text_ok = [&](const std::string& t) {
        for (char c : t) if (!std::isspace(static_cast<unsigned char>(c))) return false;
        return true;
    };
    while (i < x.size()) {
        std::size_t lt = x.find('<', i);
        std::string text = x.substr(i, (lt == std::string::npos ? x.size() : lt) - i);
        if (!text_ok(text) && !st.empty() && (st.back().role == 2 || st.back().role == 4)) {
            m.err = "text inside <" + st.back().el + "> (the game would make a nameless pack)";
            return m;
        }
        if (lt == std::string::npos) break;
        i = lt;
        if (x.compare(i, 4, "<!--") == 0) { std::size_t e = x.find("-->", i + 4); if (e == std::string::npos) { m.err = "unterminated comment"; return m; } i = e + 3; continue; }
        if (x.compare(i, 9, "<![CDATA[") == 0) {
            if (!st.empty() && (st.back().role == 2 || st.back().role == 4)) { m.err = "CDATA inside <" + st.back().el + ">"; return m; }
            std::size_t e = x.find("]]>", i + 9);
            if (e == std::string::npos) { m.err = "unterminated CDATA"; return m; }
            i = e + 3;
            continue;
        }
        if (x.compare(i, 2, "<?") == 0) { std::size_t e = x.find("?>", i + 2); if (e == std::string::npos) { m.err = "unterminated PI"; return m; } i = e + 2; continue; }
        if (x.compare(i, 2, "<!") == 0) { std::size_t e = x.find('>', i); if (e == std::string::npos) { m.err = "unterminated declaration"; return m; } i = e + 1; continue; }
        // A tag; respect quotes when looking for its end.
        std::size_t e = i + 1;
        char q = 0;
        for (; e < x.size(); ++e) {
            if (q) { if (x[e] == q) q = 0; }
            else if (x[e] == '"' || x[e] == '\'') q = x[e];
            else if (x[e] == '>') break;
        }
        if (e >= x.size()) { m.err = "unterminated tag"; return m; }
        std::string tag = x.substr(i + 1, e - i - 1);
        i = e + 1;
        if (!tag.empty() && tag[0] == '/') {
            if (st.empty()) { m.err = "unbalanced close tag"; return m; }
            if (st.back().role == 4) cur_loc = -1;
            st.pop_back();
            continue;
        }
        bool self = !tag.empty() && tag.back() == '/';
        std::size_t ne = 0;
        while (ne < tag.size() && !std::isspace(static_cast<unsigned char>(tag[ne])) && tag[ne] != '/') ++ne;
        std::string el = tag.substr(0, ne);
        std::map<std::string, std::string> at;
        if (el.empty() || !attrs(tag, ne, at)) { m.err = "malformed tag <" + tag.substr(0, 40) + ">"; return m; }
        int parent = st.empty() ? -1 : st.back().role;
        int role = 0;
        if (st.empty()) {
            if (el == "dlc") { role = 1; ++n_dlc; m.root = el; }
            else if (m.root.empty()) m.root = el;
        } else if (parent == 1 && el == "mandatory") { role = 2; ++n_mand; }
        else if (parent == 1 && el == "locations") { role = 3; ++n_locs; }
        else if (parent == 2) m.mandatory.push_back(at.count("name") ? at["name"] : std::string());
        else if (parent == 3) {
            role = 4;
            m.locations.push_back({at.count("name") ? at["name"] : std::string(), {}});
            cur_loc = static_cast<int>(m.locations.size()) - 1;
        } else if (parent == 4 && cur_loc >= 0) {
            m.locations[cur_loc].second.push_back(at.count("name") ? at["name"] : std::string());
        }
        if (!self) st.push_back({el, role});
        else if (role == 4) cur_loc = -1;
    }
    if (!st.empty()) { m.err = "unclosed elements"; return m; }
    if (n_dlc != 1) { m.err = n_dlc ? "more than one <dlc>" : "no <dlc> root (root is <" + m.root + ">)"; return m; }
    if (n_mand > 1 || n_locs != 1) { m.err = "expected one <locations> and at most one <mandatory> (the game uses only the first)"; return m; }
    m.root = "dlc";
    m.ok = true;
    return m;
}

} // namespace

void BaldMirror::set_dirs(std::vector<std::string> dirs) {
    std::lock_guard<std::mutex> g(mu_);
    dirs_ = std::move(dirs);
    cache_.clear();
}

BaldPreflight BaldMirror::preflight(const std::string& n, bool require_sizes) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = cache_.find(n);
    if (it != cache_.end()) return it->second;
    BaldPreflight p = run(dirs_, n, require_sizes);
    if (p.ok)
        logi("[bald] MIRROR READY %s: index '%s', %zu/%zu assets present (%.1f MB), dir %s", n.c_str(),
             p.index_bytes.c_str(), p.present, p.assets, p.bytes_total / 1048576.0, p.dir.c_str());
    else
        logw("[bald] mirror NOT used for %s (BALD keeps waiting, nothing is touched):", n.c_str());
    for (const auto& f : p.fails) logw("[bald]   FAIL %s", f.c_str());
    for (const auto& s : p.notes) logi("[bald]   %s", s.c_str());
    cache_[n] = p;
    return p;
}

BaldPreflight BaldMirror::run(const std::vector<std::string>& dirs, const std::string& n, bool require_sizes) {
    BaldPreflight p;
    std::vector<std::string> found;
    std::set<std::pair<unsigned long long, unsigned long long>> inodes;
    for (std::string d : dirs) {
        if (d.empty()) continue;
        if (d.back() != '/') d.push_back('/');
        struct stat st;
        if (::stat((d + "bald___index___.txt").c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
        struct stat ds;
        if (::stat(d.c_str(), &ds) != 0) continue;
        if (!inodes.insert({static_cast<unsigned long long>(ds.st_dev), static_cast<unsigned long long>(ds.st_ino)}).second) continue;
        found.push_back(d);
    }
    if (!found.empty()) p.dir = found[0];
    auto fail = [&](const std::string& s) { p.fails.push_back(s); };
    if (p.dir.empty()) {
        std::string list;
        for (const auto& d : dirs) list += (list.empty() ? "" : ", ") + d;
        fail("no bald___index___.txt in " + list + " (restore your bald folder there)");
        return p;
    }
    const std::string D = p.dir;
    // Two distinct folders with an index: BALD reads only one of them (its base is
    // resolved inside libMC5), so accept only if their bookkeeping is byte-identical.
    for (std::size_t k = 1; k < found.size(); ++k) {
        for (const char* f : {"bald___index___.txt", "bald___version___.txt", "bald___toc___.txt", "bald___hashes___.txt"}) {
            std::string a1, a2;
            store::read_file(D + f, a1);
            store::read_file(found[k] + f, a2);
            if (a1 != a2) { fail(std::string("two different DLC folders (") + D + ", " + found[k] + ") differ in " + f); return p; }
        }
        p.notes.push_back("also found an identical folder " + found[k]);
    }
    std::string ver, idx, toc_s, hash_s;
    // H1 version
    if (!store::read_file(D + "bald___version___.txt", ver)) fail("H1 bald___version___.txt unreadable");
    else if (ver != kVersion) fail("H1 bald___version___.txt is '" + ver.substr(0, 32) + "', not '6.0.12a' (BALD would re-download and delete)");
    // H2 index: verbatim, no whitespace/BOM
    if (!store::read_file(D + "bald___index___.txt", idx) || idx.empty() || idx.size() > 64)
        fail("H2 bald___index___.txt empty or too large");
    else {
        // BALD byte-compares it, and builds the toc name from it, so allow only a safe
        // charset (no whitespace/BOM, and nothing that could split a URL path).
        bool clean = true;
        for (char c : idx)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) clean = false;
        if (!clean) fail("H2 bald___index___.txt has characters other than [0-9A-Za-z._-] (BALD compares it byte for byte)");
        p.index_bytes = idx;
    }
    // H3 toc
    Json toc;
    std::vector<std::string> names;
    if (!store::read_file(D + "bald___toc___.txt", toc_s) || toc_s.empty() || !Json::try_parse(toc_s, toc) || !toc.is_object())
        fail("H3 bald___toc___.txt missing or not a JSON object");
    else if (toc["_version"].as_string("") != kVersion) fail("H3 toc _version is not 6.0.12a");
    else if (!toc["assets"].is_array() || toc["assets"].size() == 0) fail("H3 toc has no assets");
    else
        for (const Json& a : toc["assets"].elements()) {
            if (!a.is_object() || !a["name"].is_string() || a["name"].as_string().empty()) { fail("H3 toc asset without a name"); break; }
            names.push_back(a["name"].as_string());
        }
    // H4 hashes
    Json hashes;
    std::map<std::string, std::pair<long long, int>> hmap; // name -> (file_size, count)
    if (!store::read_file(D + "bald___hashes___.txt", hash_s) || hash_s.empty() || !Json::try_parse(hash_s, hashes) || !hashes.is_array())
        fail("H4 bald___hashes___.txt missing or not a JSON array");
    else
        for (const Json& h : hashes.elements()) {
            long long fs = h["file_size"].as_int(-1), cs = h["chunk_size"].as_int(0);
            if (!h["name"].is_string() || fs < 0 || fs >= 0x7fffffffLL || cs <= 0 || !h["hashes"].is_array() ||
                static_cast<long long>(h["hashes"].size()) != (fs + cs - 1) / cs) {
                fail("H4 malformed hashes entry '" + h["name"].as_string("?") + "'");
                break;
            }
            auto& e = hmap[h["name"].as_string()];
            e.first = fs;
            ++e.second;
        }
    if (!p.fails.empty()) return p;
    // H5 + H6 + H7
    const std::string prefix = "bald_" + n + "_";
    std::set<std::string> seen, keys;
    std::map<std::string, std::string> key_to_name;
    for (const auto& nm : names) {
        if (!seen.insert(nm).second) { fail("H5 duplicate toc name " + nm); break; }
        auto h = hmap.find(nm);
        if (h == hmap.end() || h->second.second != 1) { fail("H5 toc name without exactly one hashes entry: " + nm); break; }
        if (nm.compare(0, prefix.size(), prefix) != 0) { fail("H6 toc name not for variant " + n + ": " + nm); break; }
        std::string k = toc_key(nm, prefix);
        if (k.empty()) { fail("H6 unparseable asset name " + nm); break; }
        if (k == "map_android_dlc" && nm.size() >= 2 && nm.compare(nm.size() - 2, 2, "_1") == 0)
            { fail("H7 toc names the old offline map " + nm); break; }
        // The game resolves a key to the FIRST toc entry (G:0x136e010); two entries with
        // one key would mean we validate a different file than the one it mounts.
        if (!keys.insert(k).second) { fail("H5 duplicate toc key '" + k + "' (" + key_to_name[k] + ", " + nm + ")"); break; }
        key_to_name[k] = nm;
    }
    if (!p.fails.empty()) return p;
    // Files: presence and sizes (H10), soft S1/S2.
    p.assets = names.size();
    std::vector<std::string> missing;
    for (const auto& nm : names) {
        long long want = hmap[nm].first, have = -1;
        p.bytes_total += want;
        if (file_size(D + nm, have)) {
            if (have != want && require_sizes) fail("H10 " + nm + " is " + std::to_string(have) + " B, hashes say " + std::to_string(want));
            ++p.present;
        } else {
            missing.push_back(nm);
            p.bytes_missing += want;
        }
        long long t;
        if (file_size(D + "temp_" + nm, t))
            fail("H11 a partial download temp_" + nm + " is in the folder (a ready BALD would resume and rewrite it); move it out");
    }
    // H12: every toc asset must be present. With any missing, a ready BALD queues it
    // (z0_mp packs automatically) and writes temp_ files into the player's folder.
    for (const auto& m : missing) fail("H12 missing " + m + " (restore it from your backup)");
    // H8 map entry + file
    auto mk = key_to_name.find("map_android_dlc");
    if (mk == key_to_name.end()) { fail("H8 toc has no map_android_dlc entry"); return p; }
    long long msz;
    std::string mapx;
    if (!file_size(D + mk->second, msz) || msz != hmap[mk->second].first || !store::read_file(D + mk->second, mapx))
        { fail("H8 " + mk->second + " missing or wrong size"); return p; }
    if (mapx == "<dlc/>") { fail("H7 " + mk->second + " is the old empty offline map"); return p; }
    // H9 map structure: <dlc>, one location z0_mp, every pack resolves to a toc key.
    MapScan ms = scan_map(mapx);
    {   // Structure summary for the log (element tags only; adapt the scanner if needed).
        std::string tags;
        std::size_t q = 0;
        int k = 0;
        while ((q = mapx.find('<', q)) != std::string::npos && k < 12) {
            std::size_t e = mapx.find_first_of(" />", q + 1);
            if (e == std::string::npos) break;
            if (e > q + 1 && mapx[q + 1] != '/' && mapx[q + 1] != '?' && mapx[q + 1] != '!') {
                tags += mapx.substr(q, e - q) + " ";
                ++k;
            }
            q = e;
        }
        std::string locs;
        for (const auto& l : ms.locations) locs += (locs.empty() ? "" : ",") + l.first;
        p.notes.push_back("map " + mk->second + " (" + std::to_string(mapx.size()) + " B): root <" + ms.root + ">, " +
                          std::to_string(ms.mandatory.size()) + " mandatory packs, locations [" + locs + "], first tags: " + tags);
    }
    if (!ms.ok) { fail("H9 map " + mk->second + ": " + ms.err); return p; }
    int z0 = 0;
    auto check_pack = [&](const std::string& pk, const std::string& where) {
        if (pk.empty() || !keys.count(pack_key(pk))) { fail("H9 map pack '" + pk + "' (" + where + ") has no toc entry"); return false; }
        return true;
    };
    for (const auto& pk : ms.mandatory) if (!check_pack(pk, "mandatory")) return p;
    std::set<std::string> missing_keys;
    for (const auto& m : missing) missing_keys.insert(toc_key(m, prefix));
    for (const auto& loc : ms.locations) {
        if (loc.first == "z0_mp") ++z0;
        std::size_t have = 0;
        for (const auto& pk : loc.second) {
            if (!check_pack(pk, "location " + loc.first)) return p;
            if (!missing_keys.count(pack_key(pk))) ++have;
        }
        p.locations.push_back(loc.first);
        p.notes.push_back("location " + loc.first + ": " + std::to_string(have) + "/" + std::to_string(loc.second.size()) +
                          " packs present" + (have == loc.second.size() ? " -> will mount" : " -> stays not downloaded"));
    }
    if (z0 != 1) { fail("H9 map has " + std::to_string(z0) + " locations named z0_mp (the wrapper needs exactly one; 0x1bb2990)"); return p; }
    // S5 free space (the wrapper's own gate: missing bytes + 1e6, G:0xc64570/G:0xc92a78)
    struct statvfs vf;
    if (!missing.empty() && ::statvfs(D.c_str(), &vf) == 0) {
        double freeb = static_cast<double>(vf.f_bavail) * vf.f_frsize;
        if (freeb < 1e6 + static_cast<double>(p.bytes_missing))
            p.notes.push_back("S5 free space below what BALD wants for the missing files (popupNotEnoughSpace possible)");
    }
    p.ok = p.fails.empty();
    return p;
}

} // namespace mc5
