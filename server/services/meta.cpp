// meta.cpp — the TS / Anubis meta-channel (non-HTTP), the last step to the menu.
//
// After matchmaker/quick_join_ah(server_type=ts) the client opens a TCP socket to
// the controller (our loopback listener, which routes non-HTTP connections here).
// Two protocols run on it, in order:
//
//   (A) Anubis controller — newline-delimited JSON, SERVER speaks first:
//         S->C {"action":"create connection","nonce":...}
//         C->S {"action":"login","access_token":...}
//         S->C {"action":"login",...}
//         C->S {"action":"connect game","room_id","username","nonce_type"}
//         S->C {"action":"connect game","slot":...}
//   (B) TS binary meta-protocol — frames [type:u8][len:u16 BE incl 3-byte header][payload],
//       big-endian; str=u16+bytes, blob32=u32+bytes, lz4blob=u32+LZ4 block. The client
//       sends 0x01 ClientSendInitSettings; the server pushes 0x3e config and 0x27/0x03
//       TCP_Profile (the player save). The profile is what the age/gender (first-run)
//       screen needs — MC5 never loads it over HTTP storage.
//
// This is a best-effort minimum to clear the menu hang, with heavy logging of every
// frame so a device capture pins down anything the client rejects. We NEVER send
// 0x3a (integrity request). See docs/research/02-post-auth-chain.md and
// docs/protocol/tcp-messages.md.

#include "services.hpp"

#include <cstdint>
#include <string>

#include "../core/json.hpp"
#include "../core/log.hpp"
#include "../core/server.hpp" // Conn

namespace mc5 {

namespace {

std::string hexpre(const std::string& d, std::size_t max = 48) {
    static const char* H = "0123456789abcdef";
    std::string s;
    std::size_t n = d.size() < max ? d.size() : max;
    for (std::size_t i = 0; i < n; ++i) {
        unsigned char b = static_cast<unsigned char>(d[i]);
        s.push_back(H[b >> 4]);
        s.push_back(H[b & 0xf]);
    }
    if (d.size() > max) s += "..";
    return s;
}

// --- read helpers over a Conn (buffered) ---
bool fill(Conn& c, std::string& buf, std::size_t need) {
    char tmp[4096];
    while (buf.size() < need) {
        long r = c.read(tmp, sizeof(tmp));
        if (r <= 0) return false;
        buf.append(tmp, static_cast<std::size_t>(r));
    }
    return true;
}

bool read_line(Conn& c, std::string& buf, std::string& line) {
    for (;;) {
        std::size_t nl = buf.find('\n');
        if (nl != std::string::npos) {
            line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return true;
        }
        char tmp[4096];
        long r = c.read(tmp, sizeof(tmp));
        if (r <= 0) return false;
        buf.append(tmp, static_cast<std::size_t>(r));
        if (buf.size() > (1u << 20)) return false;
    }
}

bool read_frame(Conn& c, std::string& buf, std::uint8_t& type, std::string& payload) {
    if (!fill(c, buf, 3)) return false;
    type = static_cast<std::uint8_t>(buf[0]);
    std::uint16_t len = (static_cast<std::uint8_t>(buf[1]) << 8) | static_cast<std::uint8_t>(buf[2]);
    if (len < 3) return false;
    if (!fill(c, buf, len)) return false;
    payload = buf.substr(3, static_cast<std::size_t>(len) - 3);
    buf.erase(0, len);
    return true;
}

// --- write helpers (big-endian TS framing) ---
void put_u16_be(std::string& s, std::uint16_t v) {
    s.push_back(static_cast<char>((v >> 8) & 0xff));
    s.push_back(static_cast<char>(v & 0xff));
}
void put_u32_be(std::string& s, std::uint32_t v) {
    s.push_back(static_cast<char>((v >> 24) & 0xff));
    s.push_back(static_cast<char>((v >> 16) & 0xff));
    s.push_back(static_cast<char>((v >> 8) & 0xff));
    s.push_back(static_cast<char>(v & 0xff));
}

// A literals-only LZ4 block: valid LZ4 that stores `data` uncompressed, so we need
// no LZ4 compressor. (LZ4's last sequence is literals-only; the decoder copies the
// literals and stops at end-of-input.)
std::string lz4_store(const std::string& data) {
    std::string o;
    std::size_t n = data.size();
    o.push_back(static_cast<char>((n < 15 ? n : 15) << 4));
    if (n >= 15) {
        std::size_t r = n - 15;
        while (r >= 255) { o.push_back(static_cast<char>(255)); r -= 255; }
        o.push_back(static_cast<char>(r));
    }
    o += data;
    return o;
}
std::string lz4blob(const std::string& data) {
    std::string block = lz4_store(data), o;
    put_u32_be(o, static_cast<std::uint32_t>(block.size()));
    o += block;
    return o;
}
std::string blob32(const std::string& data) {
    std::string o;
    put_u32_be(o, static_cast<std::uint32_t>(data.size()));
    o += data;
    return o;
}
std::string ts_frame(std::uint8_t type, const std::string& payload) {
    std::string o;
    o.push_back(static_cast<char>(type));
    put_u16_be(o, static_cast<std::uint16_t>(3 + payload.size()));
    o += payload;
    return o;
}

bool send_all(Conn& c, const std::string& s) { return c.write(s.data(), s.size()) > 0; }

// A fresh-account profile: structural keys present (so nested loads don't null-deref)
// but identity keys (created/alias/gender/birthdate) absent, so the client treats it
// as a new player and shows the age/gender screen. Keys from 01-phase1b §2 (loader
// G:0x6e1498). Refined from the device log.
std::string default_profile(ServerContext& ctx) {
    Json p = Json::object();
    const char* zeros[] = {"credits", "rd_currency", "sp_difficulty", "rating",
                           "rating_duel", "best_solo_rank", "best_squad_rank"};
    for (const char* k : zeros) p[k] = 0;
    const char* objs[] = {"statistics", "skill_use_time", "killsig", "season_awards",
                          "event_league", "event_milestones", "ev_chapters", "m_progress",
                          "m_challengesProgress", "inventory", "_inventory_shadow",
                          "private_profile", "daily_reward", "br_daily_reward",
                          "energy_event", "bpacks_vault", "zmb_achievments"};
    for (const char* k : objs) p[k] = Json::object();
    (void)ctx;
    return p.dump();
}

Json parse_action(const std::string& line) {
    Json j;
    if (!Json::try_parse(line, j) || !j.is_object()) return Json::object();
    return j;
}

} // namespace

void serve_meta_conn(ServerContext& ctx, Conn& c, const std::string& peer) {
    logi("meta: TS/Anubis connection from %s", peer.c_str());
    std::string buf;

    // (A) Anubis controller handshake — we greet first.
    {
        Json g = Json::object();
        g["action"] = "create connection";
        g["nonce"] = "mc5offline";
        if (!send_all(c, g.dump() + "\n")) { c.close(); return; }
    }

    bool connected = false;
    for (int i = 0; i < 16 && !connected; ++i) {
        std::string line;
        if (!read_line(c, buf, line)) { logi("meta: %s closed during handshake", peer.c_str()); c.close(); return; }
        Json m = parse_action(line);
        std::string action = m["action"].as_string();
        logi("meta: anubis <- %s", line.c_str());

        if (action == "login") {
            Json r = Json::object();
            r["action"] = "login";
            r["result"] = 0;
            r["status"] = "ok";
            if (!send_all(c, r.dump() + "\n")) { c.close(); return; }
        } else if (action == "connect game") {
            Json r = Json::object();
            r["action"] = "connect game";
            r["slot"] = "0";
            r["result"] = 0;
            r["status"] = "ok";
            if (!send_all(c, r.dump() + "\n")) { c.close(); return; }
            connected = true;
        } else {
            // Unknown control verb: acknowledge minimally and continue.
            Json r = Json::object();
            r["action"] = action.empty() ? "ack" : action;
            r["result"] = 0;
            send_all(c, r.dump() + "\n");
        }
    }
    if (!connected) { logw("meta: %s no 'connect game' within handshake budget", peer.c_str()); c.close(); return; }

    // (B) TS binary channel. Push config + profile up front (server may push any
    // time), then read and log every client frame.
    std::string cfg = ts_frame(0x3e, lz4blob("{}") + blob32("") + blob32(""));
    std::string prof = ts_frame(0x27, lz4blob(default_profile(ctx)) + blob32(""));
    logi("meta: ts -> 0x3e config (%zu B) + 0x27 profile (%zu B) [%s]", cfg.size(), prof.size(),
         hexpre(prof, 24).c_str());
    if (!send_all(c, cfg) || !send_all(c, prof)) { c.close(); return; }

    for (;;) {
        std::uint8_t type = 0;
        std::string payload;
        if (!read_frame(c, buf, type, payload)) { logi("meta: %s TS channel closed", peer.c_str()); break; }
        logi("meta: ts <- type=0x%02x len=%zu [%s]", type, payload.size(), hexpre(payload).c_str());
        // We never send 0x3a (integrity). Other client frames are logged; a fuller
        // responder (inventory/tournaments/economy) is M1.
    }
    c.close();
}

} // namespace mc5
