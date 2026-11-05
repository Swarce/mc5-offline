// profile.cpp — see profile.hpp. Formats: docs/research/04-progression.md.
#include "profile.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>

#include "../core/log.hpp"
#include "../core/lz4.hpp"
#include "../core/store.hpp"
#include "ts_codec.hpp"

namespace mc5 {

namespace {

// settingsVersion 2: "bald.serve" defaults to false (the empty DLC map crashed the menu,
// device round adee827). A settings.json written by version 1 carried the old default
// "serve":true, which is not a player's choice, so it is migrated (dropped) on load.
constexpr long long kSettingsVersion = 2;
const char* kDefaultSettings = R"JSON({
 "settingsVersion":2,
 "redeem":{"enabled":true,"codes":{},"popup":"auto"},
 "unlockAll":false,
 "unlocks":{"batchSize":400,"batchDelayMs":250,"startDelaySeconds":10,"live":true},
 "economy":{"xpMultiplier":1.0,"spMultiplier":1.0,"startCredits":0,"startGold":0,
            "codeCredits":1000000,"codeGold":100000,"purchases":"none"},
 "profile":{"send":true},
 "config":{"sendGame":true},
 "bald":{"serve":false,"holdMs":2000}
})JSON";

constexpr long long kCurrencyCap = 2000000000LL;
// In-game CREDITS (soft, green) is the inventory item "diamond_dust"; in-game GOLD
// (hard) is the item "credits" (gift handler 0x5e7340: soft_currency -> diamond_dust,
// hard_currency -> credits).
const char* kClassNames[] = {"assault", "heavy", "recon", "sniper", "support", "mercenary",
                             "sapper", "morph", "paladin", "enforcer", "tracker"};
const char* kSoft = "diamond_dust";
const char* kHard = "credits";

std::string iso_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char b[32];
    std::strftime(b, sizeof(b), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return b;
}

// Deep merge: values in `over` replace those in `base`; objects merge recursively.
void merge_into(Json& base, const Json& over) {
    if (!over.is_object()) return;
    for (const auto& kv : over.items()) {
        if (kv.second.is_object() && base[kv.first].is_object()) merge_into(base[kv.first], kv.second);
        else base[kv.first] = kv.second;
    }
}

Json& ensure_obj(Json& j, const char* k) {
    Json& v = j[k];
    if (!v.is_object()) v = Json::object();
    return v;
}
Json& ensure_arr(Json& j, const char* k) {
    Json& v = j[k];
    if (!v.is_array()) v = Json::array();
    return v;
}

long long clamp_i32(long long v) {
    if (v < 0) return 0;
    if (v > 0x7fffffffLL) return 0x7fffffffLL;
    return v;
}

// An integer from a stats object, accepting both a flat dotted key ("xp.rewards") and
// the nested form ({"xp":{"rewards":N}}).
long long stat_int(const Json& stats, const std::string& dotted) {
    if (stats.contains(dotted) && stats[dotted].is_number()) return stats[dotted].as_int();
    std::size_t dot = dotted.find('.');
    if (dot == std::string::npos) return 0;
    const Json& a = stats[dotted.substr(0, dot)];
    const Json& b = a[dotted.substr(dot + 1)];
    return b.is_number() ? b.as_int() : 0;
}

void add_int_stats(Json& dst, const Json& src) {
    if (!src.is_object()) return;
    for (const auto& kv : src.items())
        if (kv.second.is_int()) dst[kv.first] = clamp_i32(dst[kv.first].as_int() + kv.second.as_int());
}

} // namespace

// ---------------------------------------------------------------------------
// Frame builders

std::string config_json() { return "{\"game\":{\"_level_up_rewards\":[{}]}}"; }

std::string frame_profile(const std::string& json) {
    if (json.find('\0') != std::string::npos) return std::string();
    if (json.size() + 4 <= ts::kMaxPayload) return ts::frame(0x03, ts::blob32(json));
    if (json.size() > 0xffffe) return std::string(); // 1 MB buffer must stay NUL-terminated
    std::string c = lz4::compress(json);
    if (c.size() + 4 > ts::kMaxPayload) return std::string();
    return ts::frame(0x27, ts::blob32(c));
}

std::string frame_inventory_changes(const Json& inv) {
    std::string json = inv.dump();
    std::string head;
    ts::put_u32(head, 0);      // F1: reason hash, 0 = silent grant (no gift popup)
    ts::put_f32le(head, 0.0f); // F2
    ts::put_u32(head, 0);      // F3
    ts::put_u32(head, 0);      // F4: 0 = apply (non-zero = error path 0x623b58)
    if (head.size() + 4 + json.size() <= ts::kMaxPayload) return ts::frame(0x45, head + ts::blob32(json));
    if (json.size() > 0xffffe) return std::string();
    std::string c = lz4::compress(json);
    if (head.size() + 4 + c.size() > ts::kMaxPayload) return std::string();
    return ts::frame(0x46, head + ts::blob32(c));
}

// ---------------------------------------------------------------------------
// 0x11 parser (lenient, boundary-checked: the client's writers never consult their
// overflow flag, so a refused string or blob can vanish from the middle of a frame).

MissionEnd parse_mission_end(const std::string& pl) {
    MissionEnd m;
    ts::Reader r(pl);
    auto stop = [&](const char* where) { m.complete = false; m.where = where; return m; };
    m.triples = r.str();
    if (!r.ok) return stop("triples");
    unsigned n2;
    if (!r.peek_u16(n2) || r.left() < 2 + n2) return stop("stats length");
    if (n2 > 0 && pl[r.p + 2] != '{') return stop("stats does not start with '{'");
    m.stats_json = r.str();
    // Section 1: per-weapon records, blob32 of 24 bytes LE {id,kills,hits,shots,time,score}.
    unsigned n = r.u8();
    for (unsigned i = 0; i < n && r.ok; ++i) {
        std::string b = r.blob();
        if (!r.ok || b.size() != 24) return stop("weapon record");
        m.weapons.push_back({ts::le32(b, 0), ts::le32(b, 4), ts::le32(b, 8), ts::le32(b, 12),
                             ts::le32(b, 16), ts::le32(b, 20)});
    }
    if (!r.ok) return stop("weapon count");
    // Section 2: 12-byte records {id,kills,score} (kept as a count only).
    n = r.u8();
    for (unsigned i = 0; i < n && r.ok; ++i) {
        std::string b = r.blob();
        if (!r.ok || b.size() != 12) return stop("section-2 record");
        ++m.n_second;
    }
    if (!r.ok) return stop("section-2 count");
    // Section 3: achievement records {u32 id, u32 tier, u8 sync, 3 pad} LE.
    n = r.u8();
    for (unsigned i = 0; i < n && r.ok; ++i) {
        std::string b = r.blob();
        if (!r.ok || b.size() != 12) return stop("achievement record");
        m.achievements.push_back({ts::le32(b, 0), ts::le32(b, 4), static_cast<unsigned char>(b[8])});
    }
    if (!r.ok) return stop("achievement count");
    // Section 4: notifications {str cat, str info, u32 key, u8 del, u8 mask}.
    n = r.u8();
    for (unsigned i = 0; i < n && r.ok; ++i) {
        r.str(); r.str(); r.u32(); r.u8(); r.u8();
        if (r.ok) ++m.n_notifs;
    }
    if (!r.ok) return stop("notifications");
    return m;
}

// ---------------------------------------------------------------------------
// Codes

std::string normalize_code(const std::string& raw) {
    std::size_t a = 0, b = raw.size();
    while (a < b && std::isspace(static_cast<unsigned char>(raw[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) --b;
    std::string s = raw.substr(a, b - a);
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

bool split_code(const std::string& code, std::string& base, int& n) {
    std::size_t i = code.size();
    while (i > 0 && std::isdigit(static_cast<unsigned char>(code[i - 1]))) --i;
    base = code.substr(0, i);
    n = 1;
    if (base.empty()) return false;
    for (char c : base) if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    if (i == code.size()) return true;
    std::string digits = code.substr(i);
    if (digits[0] == '0' || digits.size() > 6) return false; // "UNLOCKALL0", "…01" are not suffixes
    n = std::atoi(digits.c_str());
    return n >= 2;
}

namespace {
struct CodeDef { const char* code; std::vector<std::string> groups; bool currency; };
const std::vector<CodeDef>& builtin_codes() {
    // Prerequisites first (classes before their weapons, weapons before attachments),
    // as in MCVS (mercs first; UnlockMerc_ALL_MAX crashed the reward display there).
    static const std::vector<CodeDef> k = {
        {"UNLOCKALL", {"classes", "weapons", "attachments", "camos", "gear", "killsigs"}, false},
        {"UNLOCKCLASSES", {"classes"}, false},
        {"UNLOCKWEAPONS", {"classes", "weapons"}, false},
        {"UNLOCKATTACHMENTS", {"weapons", "attachments"}, false},
        {"UNLOCKCAMOS", {"camos"}, false},
        {"UNLOCKGEAR", {"gear"}, false},
        {"UNLOCKKILLSIGS", {"killsigs"}, false},
        {"UNLOCKCURRENCY", {}, true},
    };
    return k;
}
} // namespace

// ---------------------------------------------------------------------------
// Progress: settings, load, save

Progress::Progress() {
    std::lock_guard<std::mutex> g(mu_);
    load_locked();
}

void Progress::open(const std::string& dir) {
    std::lock_guard<std::mutex> g(mu_);
    dir_ = dir;
    if (!dir_.empty() && !store::mkdirs(dir_)) {
        logw("[progress] cannot create %s — keeping the save in memory only", dir_.c_str());
        dir_.clear();
    }
    load_locked();
}

std::string Progress::dir() const { std::lock_guard<std::mutex> g(mu_); return dir_; }
Json Progress::settings() const { std::lock_guard<std::mutex> g(mu_); return settings_; }

void Progress::load_locked() {
    settings_ = Json::parse(kDefaultSettings);
    model_ = Json::object();
    state_ = Json::object();
    have_profile_file_ = false;
    if (!dir_.empty()) {
        Json user;
        bool found = false;
        if (store::load_json(dir_ + "/settings.json", user, &found)) {
            long long ver = user["settingsVersion"].as_int(1);
            bool migrate = ver < kSettingsVersion;
            if (ver < 2) user.erase("bald"); // v1 wrote the old default bald.serve=true
            // MCVS aliases: assets.couponsEnabled / assets.coupons.
            const Json& assets = user["assets"];
            if (assets["couponsEnabled"].is_bool()) settings_["redeem"]["enabled"] = assets["couponsEnabled"];
            if (assets["coupons"].is_object()) settings_["redeem"]["codes"] = assets["coupons"];
            merge_into(settings_, user);
            if (migrate) {
                settings_["settingsVersion"] = kSettingsVersion;
                store::save_atomic(dir_ + "/settings.json", settings_.dump());
                logi("[progress] settings.json migrated v%lld -> v%lld (bald.serve now %s)", ver, kSettingsVersion,
                     settings_["bald"]["serve"].as_bool(false) ? "true" : "false");
            }
        } else if (!found) {
            store::save_atomic(dir_ + "/settings.json", settings_.dump());
            logi("[progress] wrote default %s/settings.json", dir_.c_str());
        }
        have_profile_file_ = store::load_json(dir_ + "/profile.json", model_);
        store::load_json(dir_ + "/state.json", state_);
        Json items;
        if (store::load_json(dir_ + "/items.json", items)) {
            ItemUniverse u;
            for (const auto& kv : items.items()) {
                if (!kv.second.is_array()) continue;
                for (const Json& e : kv.second.elements())
                    if (e.is_string() && !e.as_string().empty()) u.groups[kv.first].push_back(e.as_string());
            }
            u.source = dir_ + "/items.json";
            for (const auto& kv : u.groups) user_groups_.insert(kv.first);
            universe_ = u;
            logi("[progress] item universe from %s (%zu groups)", u.source.c_str(), u.groups.size());
        }
    }
    if (!have_profile_file_) model_ = starter_locked();
    // Normalise containers so later code can index freely.
    ensure_obj(model_, "_inventory");
    ensure_obj(model_, "inventory");
    ensure_obj(model_, "statistics");
    for (const char* k : {"general", "sp", "mp"}) ensure_obj(model_["statistics"], k);
    ensure_arr(model_, "progress");
    for (const char* k : {"redeemed", "skills_raw", "ach_raw", "loadouts", "weapon_stats", "medals", "guards"})
        ensure_obj(state_, k);
    ensure_arr(state_, "seen_0x11");
    ensure_arr(state_, "notif_raw");
    // Crash guards ("profile": the login TCP_Profile apply; "bald": serving the DLC
    // toc). A guard armed last launch and never confirmed alive means the process
    // died soon after; two such launches in a row disable that feature (logged; the
    // save is kept). Delete the entry from state.json "guards" to retry.
    for (auto& kv : state_["guards"].items_mut()) {
        Json& gd = kv.second;
        if (!gd.is_object() || !gd["pending"].as_bool()) continue;
        long long fails = gd["fails"].as_int() + 1;
        gd["fails"] = fails;
        gd["pending"] = false;
        logw("[guard] '%s' was armed on the previous launch and never confirmed (fail %lld)", kv.first.c_str(), fails);
        if (fails >= 2 && !gd["disabled"].as_bool()) {
            gd["disabled"] = true;
            loge("[guard] '%s' AUTO-DISABLED after %lld unconfirmed launches. Delete guards.%s from "
                 "MC5Offline/state.json to retry.", kv.first.c_str(), fails, kv.first.c_str());
        }
        dirty_ = true;
    }
    logi("[progress] save dir=%s profile=%s xp=%lld credits=%lld gold=%lld nodes=%zu redeemed=%zu",
         dir_.empty() ? "(memory)" : dir_.c_str(), have_profile_file_ ? "loaded" : "fresh",
         model_["_inventory"]["xp"].as_int(), model_["_inventory"][kSoft].as_int(),
         model_["_inventory"][kHard].as_int(), model_["progress"].size(), state_["redeemed"].size());
    if (dirty_) save_locked(true);
}

Json Progress::starter_locked() const {
    Json p = Json::object();
    p["_initial_country"] = country_.empty() ? std::string("US") : country_;
    p["created"] = iso_now();
    p["age"] = -1;
    p["sp_difficulty"] = 0;
    p["rating"] = 800;
    p["rating_duel"] = 800;
    p["best_solo_rank"] = 0;
    p["best_squad_rank"] = 0;
    p["best_rating"] = 0;
    p["private_profile"] = false;
    Json st = Json::object();
    st["general"] = Json::object();
    st["sp"] = Json::object();
    st["mp"] = Json::object();
    p["statistics"] = st;
    Json inv = Json::object();
    inv[kSoft] = clamp_i32(setting_int("economy", "startCredits", 0));
    inv[kHard] = clamp_i32(setting_int("economy", "startGold", 0));
    inv["xp"] = 0;
    inv["skill_points"] = 0;
    p["_inventory"] = inv;
    p["_inventory_shadow"] = Json::object();
    Json in = Json::object();
    in["current_loadout"] = 0;
    in["weapons"] = Json::object();
    p["inventory"] = in;
    p["progress"] = Json::array();
    p["achievements"] = Json::object();
    Json mt = Json::array();
    for (int i = 0; i < 3; ++i) mt.push_back(true);
    p["menu_tutorials"] = mt;
    p["menu_tutorials_skipped"] = false;
    Json dr = Json::object();
    dr["day"] = 0;
    p["daily_reward"] = dr;
    Json br = Json::object();
    br["br_day"] = 0;
    p["br_daily_reward"] = br;
    return p;
}

long long Progress::setting_int(const char* a, const char* b, long long def) const {
    const Json& v = b ? settings_[a][b] : settings_[a];
    return v.is_number() ? v.as_int() : def;
}
double Progress::setting_num(const char* a, const char* b, double def) const {
    const Json& v = b ? settings_[a][b] : settings_[a];
    return v.is_number() ? v.as_double() : def;
}
bool Progress::setting_bool(const char* a, const char* b, bool def) const {
    const Json& v = b ? settings_[a][b] : settings_[a];
    return v.is_bool() ? v.as_bool() : def;
}

void Progress::save_locked(bool force) {
    if (!dirty_ && !force) return;
    dirty_ = false;
    last_save_ = std::chrono::steady_clock::now();
    if (dir_.empty()) return;
    bool a = store::save_atomic(dir_ + "/profile.json", model_.dump());
    bool b = store::save_atomic(dir_ + "/state.json", state_.dump());
    if (a) have_profile_file_ = true;
    if (!a || !b) logw("[progress] save failed (profile=%d state=%d)", a, b);
}

void Progress::touch_locked(bool now) {
    dirty_ = true;
    if (now || std::chrono::steady_clock::now() - last_save_ >= std::chrono::seconds(1)) save_locked(true);
}

void Progress::flush(bool force) {
    std::lock_guard<std::mutex> g(mu_);
    guard_tick_locked();
    if (dirty_ || force) save_locked(true);
}

// ---------------------------------------------------------------------------
// Rendering + validation

Json Progress::render_locked() const {
    Json p = model_;
    // Loadouts: only the contiguous prefix of slots the client uploaded (0..k).
    Json lo = Json::array();
    for (int i = 0;; ++i) {
        const Json& e = state_["loadouts"][std::to_string(i)];
        if (!e.is_object()) break;
        lo.push_back(e);
    }
    if (lo.size() > 0) p["inventory"]["loadouts"] = lo;
    else p["inventory"].erase("loadouts");
    for (const char* k : {"alias", "gender", "birthdate"})
        if (p[k].is_string() && p[k].as_string().empty()) p.erase(k);
    return p;
}

Json Progress::render() const { std::lock_guard<std::mutex> g(mu_); return render_locked(); }

bool Progress::validate(const Json& p, std::string& err) {
    if (!p.is_object()) { err = "root is not an object"; return false; }
    for (const char* k : {"statistics", "_inventory", "_inventory_shadow", "inventory", "daily_reward",
                          "br_daily_reward", "achievements"})
        if (p.contains(k) && !p[k].is_object()) { err = std::string(k) + " is not an object"; return false; }
    for (const char* k : {"general", "sp", "mp"})
        if (p["statistics"].contains(k) && !p["statistics"][k].is_object()) { err = std::string("statistics.") + k; return false; }
    for (const char* k : {"progress", "menu_tutorials"})
        if (p.contains(k) && !p[k].is_array()) { err = std::string(k) + " is not an array"; return false; }
    if (p["inventory"].contains("loadouts")) {
        if (!p["inventory"]["loadouts"].is_array()) { err = "inventory.loadouts is not an array"; return false; }
        for (const Json& l : p["inventory"]["loadouts"].elements())
            if (!l.is_object()) { err = "a loadout is not an object"; return false; }
    }
    if (p.contains("private_profile") && !p["private_profile"].is_bool()) { err = "private_profile is not a bool"; return false; }
    for (const auto& kv : p["_inventory"].items()) {
        if (kv.first.empty() || kv.first[0] == '_' || kv.first == "boosts") continue;
        if (!kv.second.is_int() || kv.second.as_int() < 0 || kv.second.as_int() > 0x7fffffffLL) {
            err = "_inventory." + kv.first + " is not an int in [0, 2^31)";
            return false;
        }
    }
    for (const Json& e : p["progress"].elements())
        if (!e.is_object() || !e["node"].is_int()) { err = "progress entry without numeric node"; return false; }
    for (const Json& e : p["menu_tutorials"].elements())
        if (!e.is_bool()) { err = "menu_tutorials entry is not a bool"; return false; }
    return true;
}

// ---------------------------------------------------------------------------
// Login

void Progress::on_init_settings(const std::string& country, unsigned gate5a) {
    std::lock_guard<std::mutex> g(mu_);
    country_ = country;
    if (!country.empty() && !have_profile_file_) model_["_initial_country"] = country;
    logi("[progress] InitSettings country='%s' gate5a=%u", country.c_str(), gate5a);
}

std::string Progress::login_profile_frame(unsigned gate5a, std::string& why) {
    std::lock_guard<std::mutex> g(mu_);
    const char* env = std::getenv("MC5_TS_PROFILE");
    if (env && env[0] == '0') { why = "MC5_TS_PROFILE=0"; return std::string(); }
    if (!setting_bool("profile", "send", true)) { why = "settings profile.send=false"; return std::string(); }
    if (!guard_allowed_locked("profile")) { why = "auto-disabled by the crash guard"; return std::string(); }
    if (gate5a != 1) { why = "client did not ask (gate5a=" + std::to_string(gate5a) + ")"; return std::string(); }
    if (!have_profile_file_) { why = "first run (no stored profile yet)"; return std::string(); }
    if (model_["age"].as_int(-1) < 0) { why = "age gate not passed yet"; return std::string(); }
    Json p = render_locked();
    std::string err;
    if (!validate(p, err)) { why = "validator: " + err; loge("[progress] profile NOT sent: %s", err.c_str()); return std::string(); }
    std::string json = p.dump();
    std::string f = frame_profile(json);
    if (f.empty()) { why = "profile too large (" + std::to_string(json.size()) + " B)"; return std::string(); }
    profile_sent_ = true;
    guard_arm_locked("profile", 20); // on disk before the client applies the profile
    why = (f[0] == 0x27 ? "0x27 LZ4 " : "0x03 ") + std::to_string(json.size()) + " B JSON, frame " +
          std::to_string(f.size()) + " B";
    logi("[progress] TCP_Profile: xp=%lld credits=%lld gold=%lld items=%zu nodes=%zu loadouts=%zu",
         p["_inventory"]["xp"].as_int(), p["_inventory"][kSoft].as_int(), p["_inventory"][kHard].as_int(),
         p["_inventory"].size(), p["progress"].size(), p["inventory"]["loadouts"].size());
    return f;
}

void Progress::after_login_frame(std::uint8_t type) {
    std::lock_guard<std::mutex> g(mu_);
    // The client is past the profile apply once it starts a mission or returns to
    // the menu; otherwise the 20 s timer (guard_tick_locked) confirms it.
    if (type == 0x10 || type == 0x24) guard_confirm_locked("profile");
    guard_tick_locked();
}

bool Progress::guard_allowed(const std::string& name) const {
    std::lock_guard<std::mutex> g(mu_);
    return guard_allowed_locked(name);
}
void Progress::guard_arm(const std::string& name, int confirm_after_s) {
    std::lock_guard<std::mutex> g(mu_);
    guard_arm_locked(name, confirm_after_s);
}
bool Progress::guard_allowed_locked(const std::string& name) const {
    return !state_["guards"][name]["disabled"].as_bool();
}
void Progress::guard_arm_locked(const std::string& name, int confirm_after_s) {
    if (armed_.count(name)) return;
    armed_[name] = std::chrono::steady_clock::now() + std::chrono::seconds(confirm_after_s);
    state_["guards"][name]["pending"] = true;
    logi("[guard] '%s' armed (confirmed after %d s alive)", name.c_str(), confirm_after_s);
    save_locked(true);
}
void Progress::guard_confirm_locked(const std::string& name) {
    auto it = armed_.find(name);
    if (it == armed_.end() || it->second == std::chrono::steady_clock::time_point::max()) return;
    it->second = std::chrono::steady_clock::time_point::max(); // confirmed for this launch
    state_["guards"][name]["pending"] = false;
    state_["guards"][name]["fails"] = 0;
    logi("[guard] '%s' confirmed: the client is still alive", name.c_str());
    touch_locked(true);
}
void Progress::guard_tick_locked() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> due;
    for (const auto& kv : armed_)
        if (kv.second != std::chrono::steady_clock::time_point::max() && now >= kv.second) due.push_back(kv.first);
    for (const auto& n : due) guard_confirm_locked(n);
}

// ---------------------------------------------------------------------------
// Client frames

void Progress::on_age(std::uint32_t age, std::uint32_t gender) {
    std::lock_guard<std::mutex> g(mu_);
    if (age > 150) { logw("[progress] 0x59 age %u out of range; ignored", age); return; }
    model_["age"] = static_cast<long long>(age);
    if (gender == 1) model_["gender"] = "male";
    else if (gender == 2) model_["gender"] = "female";
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char b[16];
    std::snprintf(b, sizeof(b), "%04d-01-01", 1900 + tm.tm_year - static_cast<int>(age));
    model_["birthdate"] = b;
    logi("[progress] age=%u gender=%u birthdate=%s", age, gender, b);
    touch_locked(true);
}

void Progress::on_public_info(const std::string& json) {
    Json j;
    if (!Json::try_parse(json, j) || !j["display_name"].is_string()) return;
    std::lock_guard<std::mutex> g(mu_);
    model_["alias"] = j["display_name"].as_string();
    touch_locked(false);
}

void Progress::on_mission_start(const std::string& json) {
    Json j;
    std::string t = json;
    while (!t.empty() && (t.back() == '\n' || t.back() == '\0')) t.pop_back();
    std::lock_guard<std::mutex> g(mu_);
    in_mission_ = true;
    if (Json::try_parse(t, j) && j["node"].is_number()) {
        cur_node_ = static_cast<std::uint32_t>(j["node"].as_int());
        state_["cur_node"] = static_cast<long long>(cur_node_);
        state_["cur_level"] = j["level"].as_string("");
        logi("[progress] mission start level='%s' node=%u", j["level"].as_string("").c_str(), cur_node_);
    }
}

std::string Progress::on_mission_end(const std::string& payload) {
    MissionEnd m = parse_mission_end(payload);
    if (!m.complete)
        logw("[progress] 0x11 parse stopped at '%s' (len %zu); using what was recovered", m.where.c_str(),
             payload.size());
    Json stats;
    if (!Json::try_parse(m.stats_json, stats) || !stats.is_object()) stats = Json::object();

    std::lock_guard<std::mutex> g(mu_);
    in_mission_ = false;
    // The 0x12 values. Missing keys count 0.
    long long xp = stat_int(stats, "xp.rewards") + stat_int(stats, "xp.medals") + stat_int(stats, "xp.objectives");
    long long sp = stat_int(stats, "sp.value");
    xp = static_cast<long long>(xp * setting_num("economy", "xpMultiplier", 1.0) + 0.5);
    sp = static_cast<long long>(sp * setting_num("economy", "spMultiplier", 1.0) + 0.5);
    if (xp < 0) xp = 0;
    if (sp < 0) sp = 0;
    Json reply = Json::object();
    reply["xp"] = xp;
    reply["sp"] = sp;

    // De-duplicate: the client re-sends an identical 0x11 after a TS reset (gate+0x92).
    std::string key = std::to_string(ts::fnv1a(payload)) + ":" + std::to_string(payload.size());
    Json& seen = state_["seen_0x11"];
    for (const Json& s : seen.elements())
        if (s.is_string() && s.as_string() == key) {
            logi("[progress] 0x11 duplicate (%s): reply only, no re-apply", key.c_str());
            return reply.dump();
        }
    seen.push_back(key);
    if (seen.size() > 64) seen.elements_mut().erase(seen.elements_mut().begin());

    Json& in = inv();
    in["xp"] = clamp_i32(in["xp"].as_int() + xp);
    in["skill_points"] = clamp_i32(in["skill_points"].as_int() + sp);

    // Triples "type:id:count:" — 0 medal{hash,count}, 1 objective{1|2|3,1}, 2 list.
    bool obj2 = false, obj3 = false;
    {
        std::vector<long long> v;
        std::size_t i = 0;
        while (i < m.triples.size()) {
            std::size_t j = m.triples.find(':', i);
            if (j == std::string::npos) j = m.triples.size();
            v.push_back(std::atoll(m.triples.substr(i, j - i).c_str()));
            i = j + 1;
        }
        for (std::size_t k = 0; k + 2 < v.size(); k += 3) {
            if (v[k] == 0) {
                std::string h = std::to_string(v[k + 1]);
                state_["medals"][h] = state_["medals"][h].as_int() + v[k + 2];
            } else if (v[k] == 1) {
                if (v[k + 1] == 2) obj2 = true;
                if (v[k + 1] == 3) obj3 = true;
            }
        }
    }
    if (cur_node_) {
        Json& prog = model_["progress"];
        bool found = false;
        for (Json& e : prog.elements_mut())
            if (e["node"].as_int() == static_cast<long long>(cur_node_)) {
                if (obj2) e["objective2"] = true;
                if (obj3) e["objective3"] = true;
                found = true;
            }
        if (!found) {
            Json e = Json::object();
            e["node"] = static_cast<long long>(cur_node_);
            e["objective2"] = obj2;
            e["objective3"] = obj3;
            prog.push_back(e);
        }
    }
    for (const auto& w : m.weapons) {
        Json& ws = state_["weapon_stats"][std::to_string(w.id)];
        ws["kills"] = ws["kills"].as_int() + w.kills;
        ws["hits"] = ws["hits"].as_int() + w.hits;
        ws["shots"] = ws["shots"].as_int() + w.shots;
        ws["time_used"] = ws["time_used"].as_int() + w.time_used;
        ws["score"] = ws["score"].as_int() + w.score;
    }
    for (const auto& a : m.achievements)
        state_["ach_raw"][std::to_string(a.id) + "." + std::to_string(a.tier)] = static_cast<long long>(a.sync);
    add_int_stats(model_["statistics"]["sp"], stats);
    state_["missions_completed"] = state_["missions_completed"].as_int() + 1;
    logi("[progress] mission end node=%u: +%lld xp (total %lld), +%lld sp, weapons=%zu ach=%zu obj2=%d obj3=%d",
         cur_node_, xp, in["xp"].as_int(), sp, m.weapons.size(), m.achievements.size(), obj2, obj3);
    touch_locked(true);
    return reply.dump();
}

void Progress::on_mission_fail_stats(const std::string& json) {
    Json j;
    std::string t = json;
    while (!t.empty() && (t.back() == '\n' || t.back() == '\0')) t.pop_back();
    if (!Json::try_parse(t, j)) return;
    std::lock_guard<std::mutex> g(mu_);
    in_mission_ = false;
    add_int_stats(model_["statistics"]["sp"], j);
    touch_locked(false);
}

void Progress::on_menu_return() {
    std::lock_guard<std::mutex> g(mu_);
    in_mission_ = false;
    touch_locked(false);
}

void Progress::on_reset_b0() { std::lock_guard<std::mutex> g(mu_); ignore_next_op0_ = true; }

void Progress::on_loadout(const std::string& pl) {
    ts::Reader r(pl);
    unsigned mode = r.u8(), idx = r.u8();
    std::lock_guard<std::mutex> g(mu_);
    if (!r.ok) return;
    if (mode == 0) {
        if (ignore_next_op0_) { ignore_next_op0_ = false; logi("[progress] 0x16 op0 idx=%u after 0x22: ignored", idx); return; }
        model_["inventory"]["current_loadout"] = static_cast<long long>(idx);
        touch_locked(false);
        return;
    }
    if (mode == 1) {
        std::string s = r.str();
        Json j;
        if (!r.ok || !Json::try_parse(s, j) || !j.is_object()) {
            logw("[progress] 0x16 loadout %u without a valid JSON (client writer overflow?) — kept the old one", idx);
            return;
        }
        state_["loadouts"][std::to_string(idx)] = j;
        logi("[progress] loadout %u saved (%zu B)", idx, s.size());
        touch_locked(false);
    }
}

void Progress::on_skill(unsigned cls, unsigned skill, unsigned tier) {
    std::lock_guard<std::mutex> g(mu_);
    state_["skills_raw"][std::to_string(cls) + "." + std::to_string(skill)] = static_cast<long long>(tier);
    touch_locked(false);
}

void Progress::on_achievement(std::uint32_t id, std::uint32_t tier, unsigned sync) {
    std::lock_guard<std::mutex> g(mu_);
    state_["ach_raw"][std::to_string(id) + "." + std::to_string(tier)] = static_cast<long long>(sync);
    touch_locked(false);
}

void Progress::on_notification(const std::string& pl) {
    ts::Reader r(pl);
    Json n = Json::object();
    n["name"] = r.str();
    n["data"] = r.str();
    n["value"] = static_cast<long long>(r.u32());
    n["flag"] = static_cast<long long>(r.u8());
    n["op"] = static_cast<long long>(r.u8());
    if (!r.ok) return;
    std::lock_guard<std::mutex> g(mu_);
    Json& l = state_["notif_raw"];
    l.push_back(n);
    if (l.size() > 100) l.elements_mut().erase(l.elements_mut().begin());
    touch_locked(false);
}

void Progress::on_menu_tutorials(const std::string& pl) {
    ts::Reader r(pl);
    unsigned n = r.u8();
    Json a = Json::array();
    for (unsigned i = 0; i < n && r.ok; ++i) a.push_back(r.u8() != 0);
    if (!r.ok || n == 0 || n > 8) return;
    std::lock_guard<std::mutex> g(mu_);
    model_["menu_tutorials"] = a;
    touch_locked(false);
}

void Progress::on_difficulty(unsigned d) {
    std::lock_guard<std::mutex> g(mu_);
    model_["sp_difficulty"] = static_cast<long long>(d);
    touch_locked(false);
}

bool Progress::in_mission() const { std::lock_guard<std::mutex> g(mu_); return in_mission_; }

// ---------------------------------------------------------------------------
// Unlock codes

void Progress::set_universe(ItemUniverse u) {
    std::lock_guard<std::mutex> g(mu_);
    std::size_t n = 0;
    for (const auto& kv : u.groups) n += kv.second.size();
    logi("[progress] item universe from %s: %zu names in %zu groups, catalog %zu", u.source.c_str(), n,
         u.groups.size(), u.catalog.size());
    // The dump is written for the player to inspect (and to copy into items.json).
    if (!dir_.empty() && store::mkdirs(dir_ + "/dumps")) {
        Json d = Json::object();
        for (const auto& kv : u.groups) {
            Json a = Json::array();
            for (const auto& s : kv.second) a.push_back(s);
            d[kv.first] = a;
        }
        store::save_atomic(dir_ + "/dumps/items.json", d.dump());
    }
    // Groups the player supplied in items.json take precedence over the dump.
    for (const std::string& grp : user_groups_) {
        auto it = universe_.groups.find(grp);
        if (it != universe_.groups.end()) u.groups[grp] = it->second;
    }
    for (const auto& c : universe_.catalog) u.catalog.insert(c);
    universe_ = std::move(u);
}

ItemUniverse Progress::universe() const { std::lock_guard<std::mutex> g(mu_); return universe_; }

RedeemOutcome Progress::grant_locked(const std::string& code, const std::vector<std::string>& groups,
                                     const Json& custom_items, long long credits, long long gold, bool record) {
    RedeemOutcome o;
    o.code = code;
    Json& in = inv();
    std::vector<std::pair<std::string, long long>> grants; // absolute counts, send order
    std::set<std::string> seen;
    auto want = [&](const std::string& name, long long count) {
        if (name.empty() || name[0] == '_' || name == "boosts" || seen.count(name)) return;
        seen.insert(name);
        if (in[name].as_int() >= count) return; // already owned
        grants.emplace_back(name, count);
    };
    std::vector<std::string> missing;
    for (const std::string& grp : groups) {
        auto it = universe_.groups.find(grp);
        if (it != universe_.groups.end() && !it->second.empty()) {
            for (const std::string& n : it->second) want(n, 1);
        } else if (grp == "classes") {
            // A soldier class is owned when skills.bin marks it free (unlockLevel 1) or
            // the inventory holds an item named exactly after it (0x5d47b0 -> 0x5e5c90);
            // the 11 names are the client's own identifiers (0x843160).
            for (const char* n : kClassNames) want(n, 1);
        } else {
            missing.push_back(grp);
        }
    }
    if (custom_items.is_object())
        for (const auto& kv : custom_items.items())
            if (kv.second.is_number()) want(kv.first, clamp_i32(kv.second.as_int()));
    if (credits > 0) grants.emplace_back(kSoft, std::min(kCurrencyCap, in[kSoft].as_int() + credits));
    if (gold > 0) grants.emplace_back(kHard, std::min(kCurrencyCap, in[kHard].as_int() + gold));
    if (!missing.empty()) {
        std::string m;
        for (const auto& s : missing) m += (m.empty() ? "" : ",") + s;
        logw("[redeem] %s: no item list for group(s) %s yet (the in-game item dump has not run, and there "
             "is no items.json)", code.c_str(), m.c_str());
    }
    if (grants.empty()) {
        o.reason = missing.empty() ? "nothing left to grant (all owned)" : "no item list available";
        // Nothing to give: still a valid code if everything is owned; invalid if we
        // simply cannot resolve it (so the player can retry after the dump).
        o.valid = missing.empty();
        if (o.valid && record) {
            Json rec = Json::object();
            rec["at"] = iso_now();
            rec["items"] = 0;
            state_["redeemed"][code] = rec;
            touch_locked(true);
        }
        return o;
    }
    // Write-ahead: the save holds the grant before any frame goes out.
    for (const auto& gkv : grants) in[gkv.first] = gkv.second;
    o.credits = credits;
    o.gold = gold;
    o.items = static_cast<int>(grants.size());
    // A code whose item list is only partly known is not consumed, so redeeming it
    // again after the in-game dump grants the rest (owned items are skipped).
    if (record && missing.empty()) {
        Json rec = Json::object();
        rec["at"] = iso_now();
        rec["items"] = static_cast<long long>(grants.size());
        state_["redeemed"][code] = rec;
    }
    touch_locked(true);
    o.valid = true;
    // Live frames: batches of <= unlocks.batchSize keys, prerequisite order kept.
    // The client's apply (0x5d2ba0 -> SetCount 0x5cf5d0 with no re-sort until the frame
    // ends) appends new items unsorted but binary-searches the whole vector, so a key
    // that already exists client-side can be missed after an append in the SAME frame
    // and inserted twice. Currencies always exist, so they travel in a frame of their
    // own; unlock items are new by construction (owned ones are skipped above).
    if (setting_bool("unlocks", "live", true)) {
        std::size_t bs = static_cast<std::size_t>(std::max<long long>(1, setting_int("unlocks", "batchSize", 400)));
        std::vector<std::pair<std::string, long long>> items, money;
        for (const auto& gkv : grants)
            (gkv.first == kSoft || gkv.first == kHard ? money : items).push_back(gkv);
        for (const auto* part : {&items, &money}) {
            for (std::size_t i = 0; i < part->size(); i += bs) {
                Json batch = Json::object();
                for (std::size_t k = i; k < part->size() && k < i + bs; ++k) batch[(*part)[k].first] = (*part)[k].second;
                std::string f = frame_inventory_changes(batch);
                if (f.empty()) { logw("[redeem] batch %zu too large; it applies at the next launch", i / bs); continue; }
                o.frames.push_back(f);
            }
        }
    }
    // Reward popup (0x54): RedeemRewardPopup 0x9624e8 dereferences the catalog entry
    // for shop_name with no NULL check, so only name an item the catalog defines.
    std::string popup = settings_["redeem"]["popup"].as_string("auto");
    if (popup == "auto") {
        std::string pick;
        for (const auto& gkv : grants)
            if (universe_.catalog.count(gkv.first)) { pick = gkv.first; break; }
        if (!pick.empty()) {
            Json r = Json::object();
            r["shop_name"] = pick;
            r["qty"] = 1;
            o.reply54 = r.dump();
        }
    }
    o.reason = "granted " + std::to_string(grants.size()) + " item(s)";
    return o;
}

RedeemOutcome Progress::redeem(const std::string& raw) {
    std::lock_guard<std::mutex> g(mu_);
    RedeemOutcome o;
    o.code = normalize_code(raw);
    if (!settings_["redeem"]["enabled"].as_bool(true)) { o.reason = "redeem codes are disabled in settings"; return o; }
    if (o.code.empty()) { o.reason = "empty code"; return o; }
    if (state_["redeemed"].contains(o.code)) { o.reason = "already redeemed on this profile"; return o; }
    // Custom codes (settings redeem.codes) match the full code first.
    const Json& custom = settings_["redeem"]["codes"];
    for (const auto& kv : custom.items()) {
        if (normalize_code(kv.first) != o.code || !kv.second.is_object()) continue;
        return grant_locked(o.code, {}, kv.second["items"], kv.second["credits"].as_int(),
                            kv.second["gold"].as_int(), true);
    }
    std::string base;
    int n = 1;
    if (!split_code(o.code, base, n)) { o.reason = "unknown code"; return o; }
    for (const CodeDef& d : builtin_codes()) {
        if (base != d.code) continue;
        long long cr = d.currency ? setting_int("economy", "codeCredits", 1000000) : 0;
        long long gd = d.currency ? setting_int("economy", "codeGold", 100000) : 0;
        return grant_locked(o.code, d.groups, Json(), cr, gd, true);
    }
    o.reason = "unknown code";
    return o;
}

bool Progress::unlock_all_pending() const {
    std::lock_guard<std::mutex> g(mu_);
    return setting_bool("unlockAll", nullptr, false) && !state_["unlockAllDone"].as_bool();
}

RedeemOutcome Progress::unlock_all_once() {
    std::lock_guard<std::mutex> g(mu_);
    RedeemOutcome o = grant_locked("unlockAll", builtin_codes()[0].groups, Json(), 0, 0, false);
    if (o.valid) { state_["unlockAllDone"] = true; touch_locked(true); }
    return o;
}

Json Progress::status() const {
    std::lock_guard<std::mutex> g(mu_);
    Json s = Json::object();
    s["dir"] = dir_;
    s["profile_file"] = have_profile_file_;
    s["xp"] = model_["_inventory"]["xp"].as_int();
    s["credits"] = model_["_inventory"][kSoft].as_int();
    s["gold"] = model_["_inventory"][kHard].as_int();
    s["skill_points"] = model_["_inventory"]["skill_points"].as_int();
    s["inventory_items"] = static_cast<long long>(model_["_inventory"].size());
    s["nodes"] = static_cast<long long>(model_["progress"].size());
    s["loadouts"] = static_cast<long long>(state_["loadouts"].size());
    s["age"] = model_["age"].as_int(-1);
    s["in_mission"] = in_mission_;
    s["profile_sent"] = profile_sent_;
    s["guards"] = state_["guards"];
    Json r = Json::array();
    for (const auto& kv : state_["redeemed"].items()) r.push_back(kv.first);
    s["redeemed"] = r;
    Json u = Json::object();
    for (const auto& kv : universe_.groups) u[kv.first] = static_cast<long long>(kv.second.size());
    s["universe"] = u;
    s["universe_source"] = universe_.source;
    s["unlock_all_done"] = state_["unlockAllDone"].as_bool();
    return s;
}

} // namespace mc5
