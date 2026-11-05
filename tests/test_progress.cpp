// Unit tests for the offline save (profile.cpp), the TS codec, LZ4, and the BALD
// asset replies. Formats: docs/research/04-progression.md.
#include <cstdio>
#include <cstdlib>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

#include "../server/core/json.hpp"
#include "../server/core/lz4.hpp"
#include "../server/core/store.hpp"
#include "../server/services/profile.hpp"
#include "../server/services/services.hpp"
#include "../server/services/ts_codec.hpp"
#include "check.hpp"

using mc5::Json;
namespace ts = mc5::ts;

namespace {

std::string hex(const std::string& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (unsigned char b : d) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xf]); }
    return s;
}

std::string tmpdir() {
    char t[] = "/tmp/mc5progXXXXXX";
    char* d = mkdtemp(t);
    return d ? std::string(d) + "/MC5Offline" : std::string();
}

// A synthetic 0x11 in the client's layout (builder 0xc0c2d0).
std::string mission_end_frame(const std::string& stats, int weapons) {
    std::string p = ts::str16("0:4155398577:4:1:2:1:1:3:1:");
    p += ts::str16(stats);
    p.push_back(static_cast<char>(weapons));
    for (int i = 0; i < weapons; ++i) {
        std::string rec;
        for (std::uint32_t v : {0x11223344u, 5u, 9u, 20u, 60u, 500u})
            for (int k = 0; k < 4; ++k) rec.push_back(static_cast<char>((v >> (8 * k)) & 0xff));
        p += ts::blob32(rec);
    }
    p.push_back(0);                       // section 2
    p.push_back(1);                       // achievements
    p += ts::blob32(std::string("\x0b\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00", 12));
    p.push_back(0);                       // notifications
    return p;
}

// Decodes a 0x45/0x46 grant frame back to its JSON (checks F1..F4 == 0).
bool decode_grant(const std::string& f, Json& out) {
    if (f.size() < 3 + 20) return false;
    std::string pl = f.substr(3);
    if (pl.substr(0, 16) != std::string(16, '\0')) return false;
    ts::Reader r(pl);
    r.bytes(16);
    std::string blob = r.blob();
    if (!r.ok) return false;
    std::string json = blob;
    if (static_cast<unsigned char>(f[0]) == 0x46 && !mc5::lz4::decompress(blob, json, 1 << 20)) return false;
    return Json::try_parse(json, out);
}

} // namespace

int main() {
    // --- FNV-1a (the client's item / node hash) ---
    CHECK_EQ(ts::fnv1a("Venice_01_Intro"), 363515348u);
    CHECK_EQ(ts::fnv1a("credits"), 1358361813u);
    CHECK_EQ(ts::fnv1a("rd_currency"), 435383767u);

    // --- LZ4 round trip ---
    {
        std::string big;
        for (int i = 0; i < 4000; ++i) big += "\"weapon_" + std::to_string(i % 97) + "#att_" + std::to_string(i % 13) + "\":1,";
        for (const std::string& in : {std::string(), std::string("a"), std::string("abcdefghijklmnop"),
                                      std::string(200, 'x'), big}) {
            std::string c = mc5::lz4::compress(in), back;
            CHECK(mc5::lz4::decompress(c, back, 1 << 22));
            CHECK(back == in);
        }
        CHECK(mc5::lz4::compress(big).size() * 4 < big.size()); // real compression
        std::string garbage("\xf0\x01\x02", 3), back;
        CHECK(!mc5::lz4::decompress(garbage, back, 1 << 20));
    }

    // --- TCP_Config bytes (the Profile->stats crash fix) ---
    CHECK_EQ(hex(ts::frame(0x3e, ts::blob32(mc5::config_json()))),
             std::string("3e002a000000237b2267616d65223a7b225f6c6576656c5f75705f72657761726473223a5b7b7d5d7d7d"));

    // --- 0x11 parser ---
    {
        mc5::MissionEnd m = mc5::parse_mission_end(mission_end_frame("{\"xp.rewards\":100}", 2));
        CHECK(m.complete);
        CHECK_EQ(m.weapons.size(), std::size_t(2));
        CHECK_EQ(m.weapons[0].id, 0x11223344u);
        CHECK_EQ(m.weapons[0].score, 500u);
        CHECK_EQ(m.achievements.size(), std::size_t(1));
        CHECK_EQ(m.achievements[0].id, 11u);
        CHECK_EQ(m.achievements[0].sync, 1u);
        // A vanished stats string (writer overflow) misaligns: detected, not crashed.
        std::string bad = ts::str16("0:1:1:") + std::string("\x00\x05xxxxx", 7);
        mc5::MissionEnd b = mc5::parse_mission_end(bad);
        CHECK(!b.complete);
        mc5::MissionEnd t = mc5::parse_mission_end(std::string("\x00", 1));
        CHECK(!t.complete);
    }

    // --- codes ---
    {
        CHECK_EQ(mc5::normalize_code("  unlockall2 \n"), std::string("UNLOCKALL2"));
        std::string base;
        int n = 0;
        CHECK(mc5::split_code("UNLOCKALL", base, n) && base == "UNLOCKALL" && n == 1);
        CHECK(mc5::split_code("UNLOCKALL2", base, n) && base == "UNLOCKALL" && n == 2);
        CHECK(mc5::split_code("UNLOCKALL12", base, n) && n == 12);
        CHECK(!mc5::split_code("UNLOCKALL1", base, n));
        CHECK(!mc5::split_code("UNLOCKALL02", base, n));
        CHECK(!mc5::split_code("12", base, n));
    }

    // --- validator ---
    {
        std::string err;
        mc5::Progress fresh;
        Json p = fresh.render();
        CHECK(mc5::Progress::validate(p, err));
        CHECK(p["private_profile"].is_bool());
        p["private_profile"] = Json::object(); // the old default_profile() bug
        CHECK(!mc5::Progress::validate(p, err));
        Json q = fresh.render();
        q["_inventory"]["credits"] = -5;
        CHECK(!mc5::Progress::validate(q, err));
        Json r = fresh.render();
        r["progress"] = Json::object();
        CHECK(!mc5::Progress::validate(r, err));
    }

    const std::string dir = tmpdir();
    CHECK(!dir.empty());

    // --- first run: nothing stored -> no profile; after the age gate -> stored ---
    {
        mc5::Progress pr;
        pr.open(dir);
        CHECK(mc5::store::exists(dir + "/settings.json"));
        std::string why;
        CHECK(pr.login_profile_frame(1, why).empty());
        pr.on_init_settings("CA", 1);
        pr.on_age(20, 2);
        pr.on_public_info("{\"display_name\":\"SOLDIER_44725\"}\n");
        pr.on_reset_b0();
        pr.on_loadout(std::string("\x00\x00", 2)); // op0 right after 0x22: ignored
        std::string lo = std::string("\x01\x00", 2) + ts::str16("{\"bodyitems\":[\"assault_arms_A\"]}");
        pr.on_loadout(lo);
        pr.on_loadout(std::string("\x01\x02", 2) + ts::str16("{\"id\":2}")); // slot 2 without slot 1
        pr.on_loadout(std::string("\x00\x01", 2));                            // select loadout 1
        pr.on_menu_tutorials(std::string("\x03\x00\x01\x01", 4));
        pr.on_difficulty(2);
        pr.on_mission_start("{\"level\":\"Venice_01_Intro\",\"node\":363515348}\n");
        CHECK(pr.in_mission());
        std::string reply = pr.on_mission_end(mission_end_frame(
            "{\"xp.rewards\":100,\"xp.medals\":40,\"xp.objectives\":10,\"sp.value\":2,\"kill.total\":7}", 1));
        CHECK_EQ(reply, std::string("{\"xp\":150,\"sp\":2}"));
        CHECK(!pr.in_mission());
        // A duplicate 0x11 (resent after a TS reset): same reply, applied once.
        CHECK_EQ(pr.on_mission_end(mission_end_frame(
            "{\"xp.rewards\":100,\"xp.medals\":40,\"xp.objectives\":10,\"sp.value\":2,\"kill.total\":7}", 1)), reply);
        pr.flush(true);
        Json st = pr.status();
        CHECK_EQ(st["xp"].as_int(), 150);
        CHECK_EQ(st["skill_points"].as_int(), 2);
        CHECK_EQ(st["nodes"].as_int(), 1);
    }
    {
        Json disk;
        CHECK(mc5::store::load_json(dir + "/profile.json", disk));
        CHECK_EQ(disk["age"].as_int(), 20);
        CHECK_EQ(disk["gender"].as_string(), std::string("female"));
        CHECK_EQ(disk["alias"].as_string(), std::string("SOLDIER_44725"));
        CHECK_EQ(disk["_initial_country"].as_string(), std::string("CA"));
    }

    // --- second launch: the profile goes out at login (gate5a=1 only) ---
    {
        mc5::Progress pr;
        pr.open(dir);
        std::string why;
        CHECK(pr.login_profile_frame(0, why).empty());
        std::string f = pr.login_profile_frame(1, why);
        CHECK(!f.empty());
        CHECK_EQ(static_cast<unsigned char>(f[0]), 0x03);
        ts::Reader r(f);
        r.u8();
        CHECK_EQ(r.u16(), f.size());
        Json p;
        CHECK(Json::try_parse(r.blob(), p));
        std::string err;
        CHECK(mc5::Progress::validate(p, err));
        CHECK_EQ(p["_inventory"]["xp"].as_int(), 150);
        CHECK_EQ(p["progress"].size(), std::size_t(1));
        CHECK_EQ(p["progress"].at(0)["node"].as_int(), 363515348);
        CHECK(p["progress"].at(0)["objective2"].as_bool());
        CHECK(p["progress"].at(0)["objective3"].as_bool());
        CHECK_EQ(p["inventory"]["loadouts"].size(), std::size_t(1)); // contiguous prefix only
        CHECK_EQ(p["inventory"]["loadouts"].at(0)["bodyitems"].at(0).as_string(), std::string("assault_arms_A"));
        CHECK_EQ(p["inventory"]["current_loadout"].as_int(), 1);
        CHECK(!p["menu_tutorials"].at(0).as_bool() && p["menu_tutorials"].at(1).as_bool());
        CHECK_EQ(p["sp_difficulty"].as_int(), 2);
        CHECK_EQ(p["statistics"]["sp"]["kill.total"].as_int(), 7);
        CHECK_EQ(p["birthdate"].as_string().size(), std::size_t(10));
        // Not confirmed alive (no 0x10/0x24, no 20 s) -> pending on disk.
        Json state;
        CHECK(mc5::store::load_json(dir + "/state.json", state));
        CHECK(state["guards"]["profile"]["pending"].as_bool());
        pr.after_login_frame(0x24); // back in the menu: confirmed
        CHECK(mc5::store::load_json(dir + "/state.json", state));
        CHECK(!state["guards"]["profile"]["pending"].as_bool());
    }

    // --- crash guard: two launches that die after the profile disable it ---
    {
        for (int i = 0; i < 2; ++i) {
            mc5::Progress pr;
            pr.open(dir);
            std::string why;
            CHECK(!pr.login_profile_frame(1, why).empty()); // process "dies" here
        }
        mc5::Progress pr;
        pr.open(dir);
        std::string why;
        CHECK(pr.login_profile_frame(1, why).empty());
        CHECK(why.find("crash guard") != std::string::npos);
        // Re-enable the way the log tells the player to.
        Json state;
        CHECK(mc5::store::load_json(dir + "/state.json", state));
        state["guards"].erase("profile");
        CHECK(mc5::store::save_atomic(dir + "/state.json", state.dump()));
    }

    // --- unlock codes ---
    {
        mc5::Progress pr;
        pr.open(dir);
        mc5::RedeemOutcome o = pr.redeem(" unlockcurrency ");
        CHECK(o.valid);
        CHECK_EQ(o.code, std::string("UNLOCKCURRENCY"));
        CHECK_EQ(o.frames.size(), std::size_t(1));
        Json g;
        CHECK(decode_grant(o.frames[0], g));
        CHECK_EQ(g["diamond_dust"].as_int(), 1000000);
        CHECK_EQ(g["credits"].as_int(), 100000);
        CHECK(o.reply54.empty()); // no catalog entry known -> no popup (it would crash)
        CHECK(!pr.redeem("UNLOCKCURRENCY").valid);      // once per profile
        CHECK(pr.redeem("unlockcurrency2").valid);      // suffix redeems again
        CHECK_EQ(pr.status()["credits"].as_int(), 2000000);
        CHECK(!pr.redeem("NOTACODE").valid);
        CHECK(!pr.redeem("").valid);
        // Classes need no dump (the 11 class names are the client's own identifiers).
        mc5::RedeemOutcome cl = pr.redeem("UNLOCKCLASSES");
        CHECK(cl.valid);
        CHECK_EQ(cl.items, 11);
        Json cj;
        CHECK(decode_grant(cl.frames.at(0), cj));
        CHECK_EQ(cj["tracker"].as_int(), 1);
        // No weapon list yet: invalid and NOT consumed.
        mc5::RedeemOutcome w = pr.redeem("UNLOCKWEAPONS");
        CHECK(!w.valid);
        mc5::ItemUniverse u;
        u.source = "test";
        u.groups["classes"] = {"assault", "heavy"};
        for (int i = 0; i < 900; ++i) u.groups["weapons"].push_back("wpn_" + std::to_string(i));
        u.catalog.insert("heavy");
        pr.set_universe(u);
        w = pr.redeem("UNLOCKWEAPONS");
        CHECK(w.valid);
        CHECK_EQ(w.items, 900); // the universe's classes are already owned
        CHECK_EQ(w.frames.size(), std::size_t(3)); // 400-key batches
        Json b0;
        CHECK(decode_grant(w.frames[0], b0));
        CHECK_EQ(b0.items().front().first, std::string("wpn_0"));
        CHECK(w.reply54.empty()); // "heavy" is in the catalog but was not granted now
        CHECK(!pr.redeem("UNLOCKWEAPONS").valid);
        // UNLOCKCLASSES2: everything owned -> valid, nothing to send.
        mc5::RedeemOutcome c = pr.redeem("UNLOCKCLASSES2");
        CHECK(c.valid);
        CHECK(c.frames.empty());
        // The popup names a granted catalog item only.
        mc5::ItemUniverse u2 = u;
        u2.groups["camos"] = {"camo_a", "camo_b"};
        u2.catalog.insert("camo_b");
        pr.set_universe(u2);
        mc5::RedeemOutcome cm = pr.redeem("UNLOCKCAMOS");
        CHECK_EQ(cm.reply54, std::string("{\"shop_name\":\"camo_b\",\"qty\":1}"));
        // The big profile now needs the LZ4 frame and still round-trips.
        std::string why;
        pr.on_age(25, 1);
        std::string f = pr.login_profile_frame(1, why);
        CHECK(!f.empty());
        Json pj = pr.render();
        CHECK_EQ(pj["_inventory"]["wpn_899"].as_int(), 1);
        CHECK_EQ(pj["_inventory"]["diamond_dust"].as_int(), 2000000);
        pr.after_login_frame(0x24);
    }

    // --- 0x46 for one oversized batch ---
    {
        Json inv = Json::object();
        for (int i = 0; i < 3000; ++i) inv["attachment_item_name_" + std::to_string(i)] = 1;
        std::string f = mc5::frame_inventory_changes(inv);
        CHECK(!f.empty());
        CHECK_EQ(static_cast<unsigned char>(f[0]), 0x46);
        Json back;
        CHECK(decode_grant(f, back));
        CHECK_EQ(back.size(), std::size_t(3000));
    }

    // --- BALD asset replies (stop the 404 retry storm) ---
    {
        mc5::Router router;
        mc5::ServerContext ctx;
        ctx.progress.open(dir);
        mc5::register_services(router, ctx);
        auto get = [&](const std::string& path) {
            mc5::Request rq;
            rq.method = "GET";
            rq.path = path;
            return router.route(rq);
        };
        const std::string pre = "/asset//assets/1924:56128:6.0.12a:android:googleplay/";
        mc5::Response a = get(pre + "bald_android_astc_h___index");
        CHECK_EQ(a.status, 200);
        CHECK_EQ(a.body, std::string("1"));
        mc5::Response t = get(pre + "bald_android_astc_h__toc_1");
        CHECK_EQ(t.status, 200);
        Json toc;
        CHECK(Json::try_parse(t.body, toc));
        CHECK_EQ(toc["toc"].at(0)["_version"].as_string(), std::string("6.0.12a"));
        CHECK_EQ(toc["toc"].at(0)["assets"].at(0)["name"].as_string(),
                 std::string("bald_android_astc_h_map_android_dlc_1"));
        CHECK_EQ(toc["hashes"].at(0)["hashes"].at(0).as_string(), std::string("04ec0d2d9673bcf019d62fdc9f3e6e09"));
        mc5::Response mp = get(pre + "bald_android_etc_l_map_android_dlc_1");
        CHECK_EQ(mp.status, 200);
        CHECK_EQ(mp.body, std::string("<dlc/>"));
        CHECK_EQ(get(pre + "bald_android_astc_h_other").status, 404);
        CHECK_EQ(get(pre + "GameOptions").status, 404);
        CHECK(get("/_mc5/status").body.find("\"progress\"") != std::string::npos);
    }

    std::string cmd = "rm -rf '" + dir.substr(0, dir.rfind('/')) + "'";
    if (std::system(cmd.c_str()) != 0) std::fprintf(stderr, "cleanup failed\n");
    return mc5test::failures();
}
