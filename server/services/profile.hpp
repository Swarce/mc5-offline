// profile.hpp — the offline server's player save: progression model, persistence,
// the login TCP_Profile, and MCVS-style unlock codes.
//
// MC5 6.0.12a has NO client-side save. The app constructor hard-sets the "TS online"
// byte (0x4e2510 strh 0x101 -> app+0x6f4), so the client uploads small deltas over
// the TS meta channel (0x16 loadout, 0x11 mission end, 0x17 skill, 0x59 age, ...)
// and expects the whole document back as TCP_Profile (0x03/0x27) at login. Until now
// the server dropped all of it, so every launch was a fresh account. This class
// keeps that document on the phone and answers the frames that need a reply.
//
// Files under <files>/MC5Offline/ (the same dir as the mc5offline.log copy, pullable
// with adb): settings.json (flags, created with defaults), profile.json (the model,
// rendered to the client), state.json (server-only bookkeeping: redeemed codes,
// mission de-dup, crash guard). Atomic writes with .bak copies (core/store.hpp).
//
// Formats are from the client's own code: docs/research/04-progression.md.
// C++17.
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "../core/json.hpp"

namespace mc5 {

// Item names the unlock codes may grant, by group ("classes", "weapons",
// "attachments", "camos", "gear"). Filled at runtime from the player's own game data
// (the embedded host reads the in-memory armory; or <dir>/items.json) — never shipped.
struct ItemUniverse {
    std::map<std::string, std::vector<std::string>> groups;
    std::set<std::string> catalog; // names the client's shop catalog defines (popup-safe)
    std::string source;            // where it came from, for the log/status
};

struct RedeemOutcome {
    bool valid = false;
    std::string code;                // normalised (trimmed, upper-case)
    std::string reason;              // human-readable, for the log
    std::vector<std::string> frames; // TS 0x45/0x46 grant frames, in send order
    std::string reply54;             // 0x54 payload JSON ("" = send none)
    int items = 0;                   // distinct items granted
    long long credits = 0, gold = 0; // currency added
};

// Parsed C->S 0x11 (mission end; builder 0xc0c2d0).
struct MissionEnd {
    std::string triples, stats_json;
    struct Weapon { std::uint32_t id, kills, hits, shots, time_used, score; };
    struct Ach { std::uint32_t id, tier; unsigned sync; };
    std::vector<Weapon> weapons;
    std::vector<Ach> achievements;
    std::size_t n_second = 0, n_notifs = 0;
    bool complete = true;            // false: a section was misaligned (logged)
    std::string where;               // where parsing stopped, if incomplete
};
MissionEnd parse_mission_end(const std::string& payload);

// Normalises a redeem code: trim, upper-case. Splits "UNLOCKALL2" -> ("UNLOCKALL", 2);
// no suffix -> n = 1.
std::string normalize_code(const std::string& raw);
bool split_code(const std::string& code, std::string& base, int& n);

// TS frame builders shared with tests.
std::string frame_inventory_changes(const Json& inv); // 0x45 plain, or 0x46 LZ4 if large
std::string frame_profile(const std::string& json);   // 0x03 plain, or 0x27 LZ4 if large
std::string config_json();                             // the TCP_Config 0x3e document

class Progress {
public:
    Progress(); // in-memory defaults until open()
    // dir = "<files>/MC5Offline" (created); "" keeps everything in memory (tests,
    // desktop host without --data-dir).
    void open(const std::string& dir);
    std::string dir() const;
    Json settings() const;

    // --- login ---
    void on_init_settings(const std::string& country, unsigned gate5a);
    // The 0x03/0x27 frame to insert in the login burst, or "" (why says why not).
    std::string login_profile_frame(unsigned gate5a, std::string& why);
    // Any client frame after login: clears the profile crash guard once the client
    // has clearly survived the apply.
    void after_login_frame(std::uint8_t type);

    // --- client frames (docs/research/04 §2) ---
    void on_age(std::uint32_t age, std::uint32_t gender);
    void on_public_info(const std::string& json);
    void on_mission_start(const std::string& json);
    std::string on_mission_end(const std::string& payload); // returns the 0x12 JSON
    void on_mission_fail_stats(const std::string& json);
    void on_menu_return();
    void on_loadout(const std::string& payload);
    void on_reset_b0();                                      // S->C 0x22 was just sent
    void on_skill(unsigned cls, unsigned skill, unsigned tier);
    void on_achievement(std::uint32_t id, std::uint32_t tier, unsigned sync);
    void on_notification(const std::string& payload);
    void on_menu_tutorials(const std::string& payload);
    void on_difficulty(unsigned d);
    bool in_mission() const;

    // --- unlock codes ---
    RedeemOutcome redeem(const std::string& raw_code);
    // settings.unlockAll: the UNLOCKALL set once per profile (state.unlockAllDone).
    bool unlock_all_pending() const;
    RedeemOutcome unlock_all_once();
    void set_universe(ItemUniverse u);
    ItemUniverse universe() const;

    // --- campaign zones (docs/research/06-zones-cheats-bots.md §A) ---
    // A zone is open iff zone == 0 or inventory "unlocked_zones" >= zone (0x8e2688);
    // the client never raises the count itself. The host walks the game's own zone
    // table (story node ids per zone) and hands it over here; the count is then raised
    // each time every story node of zone U is in progress[].
    void set_zone_table(const std::map<int, std::vector<std::uint32_t>>& story, int ui_zone_count,
                        const std::string& source);
    // The 0x45 {"unlocked_zones":U} frame to send at a menu return ("" = none).
    std::string take_zone_push(bool first_menu_return);
    long long unlocked_zones() const;

    // --- purchases / cheats (0x41 [u32 item, u32], 0x42 [u32 item, f32]) ---
    // Returns the silent 0x45 reply (always one: it releases the client's
    // "tranzaction_in_progress" lock, pm+0x170, via F1=0 at 0x5f5ac8).
    std::string on_purchase(std::uint8_t type, const std::string& payload, std::string& log);
    // Gameplay cheat toggles (written into the game's settings bytes by the host).
    struct Cheats { bool god = false, ammo = false, medkits = false; bool explicit_choice = false; };
    Cheats cheats() const;
    // Redeem codes that are commands rather than grants (repeatable): GODMODE,
    // INFINITEAMMO, INFINITEMEDKITS, CHEATSOFF, BOTMATCH, UNLOCKZONES. Returns true if
    // `code` was one; `what` says what to do ("cheats", "botmatch", "zones").
    bool command_code(const std::string& code, std::string& what, std::string& log,
                      std::vector<std::string>& frames);

    // --- crash guards (state.json "guards") ---
    bool guard_allowed(const std::string& name) const;
    void guard_arm(const std::string& name, int confirm_after_s);

    // --- persistence / diagnostics ---
    void flush(bool force = false);
    Json render() const;                 // the TCP_Profile document
    static bool validate(const Json& p, std::string& err);
    Json status() const;

private:
    void load_locked();
    void save_locked(bool force);
    void touch_locked(bool now);
    Json starter_locked() const;
    Json render_locked() const;
    RedeemOutcome grant_locked(const std::string& code, const std::vector<std::string>& groups,
                               const Json& custom_items, long long credits, long long gold,
                               bool record);
    Json& inv() { return model_["_inventory"]; }
    long long zone_cap_locked() const;
    long long zones_locked() const;
    bool recompute_zones_locked(const char* why);
    void set_unlocked_zones_locked(long long u, const char* why);
    bool guard_allowed_locked(const std::string& name) const;
    void guard_arm_locked(const std::string& name, int confirm_after_s);
    void guard_confirm_locked(const std::string& name);
    void guard_tick_locked();
    long long setting_int(const char* a, const char* b, long long def) const;
    double setting_num(const char* a, const char* b, double def) const;
    bool setting_bool(const char* a, const char* b, bool def) const;

    mutable std::mutex mu_;
    std::string dir_;
    Json settings_ = Json::object();
    Json model_ = Json::object();
    Json state_ = Json::object();
    bool have_profile_file_ = false;
    bool bald_guard_reset_ = false; // settings migrated from < v3 (see load_locked)
    bool dirty_ = false;
    std::chrono::steady_clock::time_point last_save_{};
    // session (not persisted)
    bool in_mission_ = false;
    bool ignore_next_op0_ = false;
    std::string country_;
    std::uint32_t cur_node_ = 0;
    bool profile_sent_ = false;
    std::map<std::string, std::chrono::steady_clock::time_point> armed_; // max() = confirmed
    std::string last_mission_key_;
    bool zones_push_pending_ = false;
    bool zones_pushed_this_session_ = false;
    bool defer_save_ = false; // set while called from the game thread (no fsync there)
    ItemUniverse universe_;
    std::set<std::string> user_groups_; // groups from <dir>/items.json (they win over the dump)
};

} // namespace mc5
