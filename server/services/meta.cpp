// meta.cpp — the Anubis controller + TS meta-channel (non-HTTP): the last link
// before login state 8 sees the gate object's "connected" byte (+0xEC) set.
//
// The client opens one TCP socket to the controller returned by the Federation
// sessions reply (matchmaker.cpp); our listener hands the quiet socket here
// (server.cpp). Reimplemented from the client's own code (libMC5 6.0.12a arm64):
//
//   (A) Anubis controller — one compact JSON object per '\n'-terminated line, each in
//       a single write; the SERVER speaks first. The client's reader (0xc38d00)
//       parses a whole recv batch at the first '\n' and drops anything after it, so
//       nothing may be pipelined behind a line. Success check 0xc36120: "success"
//       must be true or "true" (missing -> err 0); "result"/"status" are never read.
//         S->C {"action":"create connection","nonce":"mc5offline","success":true}
//         C->S {"access_token":..,"action":"connect game","nonce_type":"targeted",
//               "room_id":..,"username":"anonymous:.."}   (no nonce_type in mode 1)
//         S->C {"action":"connect game","slot":"0","success":true}
//       There is no "login" step (the only FSM store of that state is a failure retry).
//   (B) TS binary — frames [type u8 1..0xAD][len u16 BE incl. 3-byte header][payload],
//       big-endian; str = u16+bytes, blob32 = u32+bytes. The server must NOT send
//       binary until the client's first TS frame (always 0x01 ClientSendInitSettings)
//       arrives: until then the bytes land in the controller reader's buffer and are
//       lost, and every client TS send (0xc0be30) proves the TS reader is live.
//       Then one login burst (one write) sets the four flags state 10 (0xc07740)
//       waits for, with the player's save inserted:
//         22 00 03                          -> +0xb0, +0xb2           (0xc09da4)
//         3e 00 2a | blob32 {"game":{"_level_up_rewards":[{}]}}
//                                           -> +0xb3 TCP_Config plain (0xc0b1a8).
//                                              NOT "{}": the config parser 0x607270
//                                              returns at 0x607388 without "game", the
//                                              level-up table stays unsized, and
//                                              Profile->stats crashed at 0x95e6ec.
//         [03 | blob32 profile JSON, or 27 | blob32 LZ4] -> TCP_Profile, only when
//                                              the client asks (InitSettings gate5a=1)
//                                              and a save with a passed age gate exists
//                                              (profile.cpp; first runs send none)
//         04 00 0a | u8 0 | blob32 "[]"     -> event 2 -> +0xb1 (TCP_Tournaments,
//                                              main-thread pump 0xc05e50 -> 0xc05850)
//         4a 00 07 | u32 0                  -> +0x83, +0xb4           (0xc0adf8)
//       After that, the TS idle watchdog (0xc0bcb8) drops the link after 15 s of
//       silence, so we send the no-op frame 02 00 03 every 5 s (type 2 hits the
//       handler's default case 0xc0b5a4; the prologue refreshes +0x3c for every
//       frame) and never close the socket ourselves.
//   (C) Progression (docs/research/04-progression.md): the client uploads deltas and
//       the save (Progress, profile.cpp) applies them. Replies: 0x06 -> 07 u32 0
//       (level data: use the local packs), 0x11 -> 0x12 str {"xp","sp"} (the
//       mission-end screen waits for it with no timeout), 0x21/0x96 -> 0x22,
//       0x49 -> 0x4a, 0x53 redeem code -> 0x45/0x46 grants + 0x54 (or 0x54 "null").
//
// NEVER send: 0x3a (integrity), 0x20 (switches to the 180 s/atsv path), 0x33,
// 0x0d/0x3c with JSON (kick/ban), a 0x3e/0x3f payload of exactly "ERR" (or ""),
// S->C 0x10/0x2d with u32 != 0, a TCP_Profile mid-session (a load resets age and
// inventory), or 0x45/0x46 with F1 != 0 (gift popups with catalog lookups).
// See docs/research/02-post-auth-chain.md §15/§19 and docs/protocol/tcp-messages.md.

#include "services.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../core/json.hpp"
#include "../core/log.hpp"
#include "../core/server.hpp" // Conn
#include "ts_codec.hpp"

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

// --- write helpers: server/services/ts_codec.hpp ---
using ts::blob32;
std::string ts_frame(std::uint8_t type, const std::string& payload) { return ts::frame(type, payload); }

Json parse_action(const std::string& line) {
    Json j;
    if (!Json::try_parse(line, j) || !j.is_object()) return Json::object();
    return j;
}

std::string jstr(const Json& j, const char* k) {
    const Json& v = j[k];
    return v.is_string() ? v.as_string() : std::string();
}

using BeReader = ts::Reader;

// The two InitSettings fields the save needs: "identity" (the country, e.g. "CA")
// and gate5a (1 = the client asks for its TCP_Profile).
void init_fields(const std::string& pl, std::string& country, unsigned& gate5a) {
    BeReader r(pl);
    r.u8(); r.u8(); r.u32();
    country = r.str();
    for (int i = 0; i < 4; ++i) r.str();
    gate5a = r.u8();
    if (!r.ok) gate5a = 0;
}

// 0x01 ClientSendInitSettings (built by 0xc08008): every field, for the log.
std::string decode_init_settings(const std::string& pl) {
    BeReader r(pl);
    char b[96];
    std::string o;
    unsigned a = r.u8(), v = r.u8();
    unsigned long hc = r.u32();
    std::snprintf(b, sizeof(b), "b0=0x%02x b1=0x%02x hc_hash=0x%08lx", a, v, hc);
    o += b;
    const char* names1[] = {"identity", "lang", "client_id", "portal", "pandora"};
    for (const char* n : names1) o += std::string(" ") + n + "='" + r.str() + "'";
    std::snprintf(b, sizeof(b), " gate5a=%u", r.u8());
    o += b;
    const char* names2[] = {"device_id", "strA", "strB", "igp"};
    for (const char* n : names2) o += std::string(" ") + n + "='" + r.str() + "'";
    unsigned f1 = r.u8(), f2 = r.u8();
    unsigned long days = r.u32();
    std::snprintf(b, sizeof(b), " flag=%u zero=%u days=%lu", f1, f2, days);
    o += b;
    if (!r.ok) o += " [TRUNCATED at " + std::to_string(r.p) + "/" + std::to_string(pl.size()) + "]";
    else if (r.p != pl.size()) o += " [+" + std::to_string(pl.size() - r.p) + " trailing bytes]";
    return o;
}

// The login burst (see header): 0x22, 0x3e TCP_Config, [TCP_Profile], 0x04, 0x4a,
// in ONE write. TCP_Config must carry a "game" object: "{}" made the config parser
// 0x607270 return at 0x607388 before 0x614c78 sized the level-up-rewards table
// (cfg+0x5f8), so Profile -> stats dereferenced NULL at 0x95e6ec (§19).
std::string login_burst(const std::string& config, const std::string& profile_frame) {
    std::string o;
    o += ts_frame(0x22, "");                                      // b0, b2
    o += ts_frame(0x3e, blob32(config));                          // b3 (TCP_Config, plain)
    o += profile_frame;                                           // 0x03/0x27 or nothing
    o += ts_frame(0x04, std::string(1, '\0') + blob32("[]"));     // b1 (TCP_Tournaments)
    o += ts_frame(0x4a, std::string(4, '\0'));                    // b4 (u32 n=0)
    return o;
}

std::string printable(const std::string& p) {
    static const char* H = "0123456789abcdef";
    std::string out;
    for (unsigned char b : p) {
        if (b >= 0x20 && b < 0x7f && b != '\\') out.push_back(static_cast<char>(b));
        else if (b == '\n') out += "\\n";
        else { out += "\\x"; out.push_back(H[b >> 4]); out.push_back(H[b & 0xf]); }
    }
    return out;
}

std::atomic<int> g_conn_seq{0};

// One meta connection: serialised writes (reader replies + keepalive thread),
// per-connection timing and the shared status block.
class MetaConn {
public:
    MetaConn(ServerContext& ctx, Conn& c, std::string peer)
        : ctx_(ctx), c_(c), peer_(std::move(peer)), id_(++g_conn_seq),
          t0_(std::chrono::steady_clock::now()) {
        std::lock_guard<std::mutex> g(ctx_.anubis.mu);
        ++ctx_.anubis.conns;
    }

    long ms() const {
        return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - t0_).count());
    }
    int id() const { return id_; }

    void phase(const std::string& p) {
        phase_ = p;
        logi("meta#%d +%ldms phase %s", id_, ms(), p.c_str());
        std::lock_guard<std::mutex> g(ctx_.anubis.mu);
        ctx_.anubis.phase = p;
    }

    bool send(const std::string& bytes, const char* what) {
        std::lock_guard<std::mutex> g(wmu_);
        bool ok = c_.write(bytes.data(), bytes.size()) > 0;
        if (!ok) logw("meta#%d +%ldms write failed (%s)", id_, ms(), what);
        return ok;
    }
    bool send_line(const Json& j) {
        std::string line = j.dump();
        logi("meta#%d +%ldms anubis -> %s", id_, ms(), line.c_str());
        return send(line + "\n", "json line");
    }
    bool send_frames(const std::string& bytes, const char* what, int nframes = 1) {
        logi("meta#%d +%ldms ts -> %s (%zu B) [%s]", id_, ms(), what, bytes.size(),
             hexpre(bytes, 32).c_str());
        if (bytes.size() > 48) log_full_out(bytes);
        bool ok = send(bytes, what);
        if (ok) { std::lock_guard<std::mutex> g(ctx_.anubis.mu); ctx_.anubis.frames_out += nframes; }
        return ok;
    }

    void start_keepalive() {
        ka_ = std::thread([this] {
            const std::string ka = ts_frame(0x02, "");
            long n = 0;
            std::unique_lock<std::mutex> lk(cvm_);
            while (!cv_.wait_for(lk, std::chrono::seconds(5), [this] { return stop_; })) {
                lk.unlock();
                bool ok = send(ka, "keepalive");
                ctx_.progress.flush(); // debounced save + profile crash-guard confirmation
                lk.lock();
                if (!ok) break;
                ++n;
                { std::lock_guard<std::mutex> g(ctx_.anubis.mu); ++ctx_.anubis.keepalives; }
                if (n == 1 || n % 12 == 0) logi("meta#%d +%ldms keepalive #%ld (02 00 03)", id_, ms(), n);
            }
        });
    }
    void stop_keepalive() {
        { std::lock_guard<std::mutex> lk(cvm_); stop_ = true; }
        cv_.notify_all();
        if (ka_.joinable()) ka_.join();
        for (auto& t : workers_) if (t.joinable()) t.join();
        workers_.clear();
    }

    // Sleeps up to ms; false if the connection is closing.
    bool wait_ms(long ms) {
        std::unique_lock<std::mutex> lk(cvm_);
        return !cv_.wait_for(lk, std::chrono::milliseconds(ms), [this] { return stop_; });
    }
    // Runs fn on a worker thread (delayed pushes: unlock batches, unlockAll).
    template <class F> void spawn(F fn) { workers_.emplace_back(std::move(fn)); }

    void finish(const char* why) {
        stop_keepalive();
        ctx_.progress.flush(true);
        logi("meta#%d %s %s after %ldms, last phase '%s'", id_, peer_.c_str(), why, ms(), phase_.c_str());
        c_.close();
    }

    ServerContext& ctx() { return ctx_; }
    // True exactly once per connection: the first 0x24 menu return.
    bool first_menu_return() { bool f = !menu_seen_; menu_seen_ = true; return f; }

    // Every server->client frame over 48 bytes in full (burst, profile, 0x12, 0x45/0x46),
    // one entry per frame, <=800-char parts, with the payload FNV for cross-checking.
    void log_full_out(const std::string& bytes) {
        std::size_t p = 0;
        while (p + 3 <= bytes.size()) {
            std::size_t len = (static_cast<unsigned char>(bytes[p + 1]) << 8) | static_cast<unsigned char>(bytes[p + 2]);
            if (len < 3 || p + len > bytes.size()) break;
            std::string pl = bytes.substr(p + 3, len - 3);
            if (pl.size() > 48) {
                std::string out = printable(pl);
                const std::size_t kChunk = 800;
                std::size_t parts = (out.size() + kChunk - 1) / kChunk;
                for (std::size_t i = 0; i < parts; ++i)
                    logi("meta#%d ts-out-full 0x%02x len=%zu fnv=%08x part %zu/%zu: %s", id_,
                         static_cast<unsigned char>(bytes[p]), pl.size(), ts::fnv1a(pl), i + 1, parts,
                         out.substr(i * kChunk, kChunk).c_str());
            }
            p += len;
        }
    }

private:
    ServerContext& ctx_;
    Conn& c_;
    std::string peer_;
    int id_;
    std::chrono::steady_clock::time_point t0_;
    std::string phase_ = "accepted";
    std::mutex wmu_;
    std::thread ka_;
    std::vector<std::thread> workers_;
    std::mutex cvm_;
    std::condition_variable cv_;
    bool stop_ = false;
    bool menu_seen_ = false;
};

// A JSON line on the controller socket (phase A, or unexpectedly in phase B).
// Returns false to close. Sets connected when "connect game" was answered.
bool handle_json_line(MetaConn& m, const std::string& line, bool& connected) {
    logi("meta#%d +%ldms anubis <- %s", m.id(), m.ms(), line.c_str());
    Json req = parse_action(line);
    std::string action = jstr(req, "action");
    Json r = Json::object();
    if (action == "connect game") {
        std::string nt = jstr(req, "nonce_type");
        std::string mode = (nt == "targeted") ? "0 (targeted)" : "1 (nonce_type='" + nt + "')";
        logi("meta#%d connect game: access_token='%s' room_id='%s' username='%s' nonce_type='%s' -> mode %s",
             m.id(), jstr(req, "access_token").c_str(), jstr(req, "room_id").c_str(),
             jstr(req, "username").c_str(), nt.c_str(), mode.c_str());
        if (nt != "targeted")
            logw("meta#%d Anubis MODE 1 — the mode flag is process-sticky; kill and restart the app", m.id());
        {
            std::lock_guard<std::mutex> g(m.ctx().anubis.mu);
            m.ctx().anubis.mode = mode;
            if (!m.ctx().anubis.token.empty() && jstr(req, "access_token") != m.ctx().anubis.token)
                logw("meta#%d access_token differs from the last issued '%s'", m.id(),
                     m.ctx().anubis.token.c_str());
        }
        r["action"] = "connect game";
        r["slot"] = "0";
        r["success"] = true;
        if (!m.send_line(r)) return false;
        connected = true;
        return true;
    }
    // Not expected: "login" is never sent by this client; anything else neither.
    logw("meta#%d unexpected controller action '%s' — acknowledging", m.id(), action.c_str());
    r["action"] = action.empty() ? std::string("ack") : action;
    r["success"] = true;
    return m.send_line(r);
}

// Long client frames carry the progression uploads (0x11, 0x16 profile JSON, ...): log
// them in full so a device run captures the exact formats. Printable runs are shown as
// text, everything else as hex; split into <=800-char lines (logcat truncates ~4 KB).
void log_full_payload(MetaConn& m, std::uint8_t type, const std::string& p) {
    std::string out = printable(p);
    const std::size_t kChunk = 800;
    std::size_t parts = (out.size() + kChunk - 1) / kChunk;
    for (std::size_t i = 0; i < parts; ++i)
        logi("meta#%d ts-full 0x%02x len=%zu part %zu/%zu: %s", m.id(), type, p.size(), i + 1, parts,
             out.substr(i * kChunk, kChunk).c_str());
}

const char* ts_name(std::uint8_t t) {
    // Client->server meta frames (docs/research/03-anubis-ts-spec.md; 04-progression.md).
    switch (t) {
        case 0x01: return "ClientSendInitSettings";
        case 0x05: return "login-cred(alt)";
        case 0x06: return "lvc-request";
        case 0x0b: return "public-info";
        case 0x10: return "mission-start";
        case 0x11: return "mission-end";
        case 0x16: return "loadout";
        case 0x17: return "skill";
        case 0x19: return "achievement";
        case 0x1a: return "notification";
        case 0x21: return "profile-wait-timeout";
        case 0x24: return "menu-return";
        case 0x2d: return "mission-start(resend)";
        case 0x32: return "menu-tutorials";
        case 0x34: return "tournaments-refresh";
        case 0x41: case 0x42: case 0x44: case 0x48: case 0x4d: return "purchase";
        case 0x49: return "request-0x4a";
        case 0x50: return "login-cred";
        case 0x52: return "app-resume";
        case 0x53: return "redeem-code";
        case 0x59: return "age-gender (AGE GATE OK)";
        case 0x5a: return "geo";
        case 0x66: return "killsig-cond";
        case 0x69: return "0x69";
        case 0x74: return "profile-ack";
        case 0x96: return "reset-b0";
        case 0xa3: return "difficulty";
        case 0xa8: return "restrictions-ok";
        case 0xac: return "mission-fail-stats";
        case 0xad: return "consent";
        default:   return "?";
    }
}

std::uint32_t be32(const std::string& p, std::size_t off) {
    if (p.size() < off + 4) return 0;
    auto b = [&](std::size_t i) { return static_cast<std::uint32_t>(static_cast<unsigned char>(p[off + i])); };
    return (b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3);
}

// Readable lines for the frames that mark progress through the first-run flow.
void log_milestone(MetaConn& m, std::uint8_t type, const std::string& p) {
    switch (type) {
        case 0xa8:
            logi("meta#%d MILESTONE restrictions-ok (0xa8): the age gate's Restrictions check "
                 "returned 0 with no blocking restriction (0xc1c6c0)", m.id());
            break;
        case 0x59:
            logi("meta#%d MILESTONE age gate passed (0x59): age=%u gender/ui=%u (sent by 0x8de9e8 "
                 "on success; the tutorial should load next)", m.id(), be32(p, 0), be32(p, 4));
            break;
        case 0xad: {
            BeReader r(p);
            std::string a = r.str(), b = r.str(), c = r.str();
            logi("meta#%d consent mirror (0xad): '%s' '%s' '%s' (fire-and-forget; no reply)",
                 m.id(), a.c_str(), b.c_str(), c.c_str());
            break;
        }
        case 0x0b: {
            BeReader r(p);
            logi("meta#%d public-info (0x0b): %s", m.id(), r.str().c_str());
            break;
        }
        default: break;
    }
}

// Sends a code's grant frames (0x45/0x46 batches, unlocks.batchDelayMs apart) and
// the 0x54 reward reply. Runs on a MetaConn worker thread. The 0x54 must arrive
// within 8 s of the 0x53 (0x79a490 checks now - [+0x138] >= 8001 ms), so if the
// batches would take longer it goes first.
void push_grants(MetaConn& m, const RedeemOutcome& o, bool reply = false) {
    long delay = static_cast<long>(m.ctx().progress.settings()["unlocks"]["batchDelayMs"].as_int(250));
    bool early = reply && static_cast<long>(o.frames.size()) * delay > 5000;
    auto send54 = [&] {
        if (!reply || o.reply54.empty()) return;
        m.send_frames(ts_frame(0x54, ts::str16(o.reply54)), "0x54 redeem reward popup");
    };
    if (early) send54();
    for (std::size_t i = 0; i < o.frames.size(); ++i) {
        if (i && !m.wait_ms(delay)) return;
        char what[64];
        std::snprintf(what, sizeof(what), "0x%02x inventory grant %zu/%zu", static_cast<unsigned char>(o.frames[i][0]),
                      i + 1, o.frames.size());
        if (!m.send_frames(o.frames[i], what)) return;
    }
    if (!early) send54();
}

// Every client frame after the login burst.
void handle_frame(MetaConn& m, std::uint8_t type, const std::string& p) {
    Progress& pr = m.ctx().progress;
    BeReader r(p);
    switch (type) {
        case 0x49: m.send_frames(ts_frame(0x4a, std::string(4, '\0')), "0x4a (reply to 0x49)"); break;
        case 0x96:
        case 0x21:
            // 0x96 reset-b0 / 0x21 profile-wait timeout: restore b0 with 0x22. The
            // client then sends 0x16 op0 with its pre-load loadout index (ignored).
            if (type == 0x21) logw("meta#%d client reports a profile-wait timeout (0x21)", m.id());
            m.send_frames(ts_frame(0x22, ""), type == 0x96 ? "0x22 (reply to 0x96, restores b0)"
                                                            : "0x22 (reply to 0x21)");
            pr.on_reset_b0();
            break;
        case 0x59: pr.on_age(be32(p, 0), be32(p, 4)); break;
        case 0x0b: pr.on_public_info(r.str()); break;
        case 0x10:
        case 0x2d: {
            pr.on_mission_start(r.str());
            // Re-assert the gameplay cheat bytes at every mission start (the game also
            // reloads its settings file, settings_new.dat).
            auto& h = m.ctx().host;
            Progress::Cheats c = pr.cheats();
            if (h.apply_cheats && (c.god || c.ammo || c.medkits)) h.apply_cheats(c.god, c.ammo, c.medkits);
            break;
        }
        case 0x06: {
            // Level-data request [str lvcName, u32 cachedVer]: answer "no server copy"
            // (07 u32 0 -> 0x831cb8, the local packs) instead of making the level
            // loader wait its 15 s timeout (gate+0x40).
            std::string lvc = r.str();
            logi("meta#%d level data request '%s' cached=0x%08x -> 0x07 size 0 (use local data)", m.id(),
                 lvc.c_str(), r.u32());
            m.send_frames(ts_frame(0x07, std::string(4, '\0')), "0x07 (no server LVC)");
            break;
        }
        case 0x11: {
            // Mission end. The outcome controller waits (no timeout) for 0x12 [str JSON]
            // before showing the stats screen; always reply, also to a duplicate.
            std::string reply = pr.on_mission_end(p);
            m.send_frames(ts_frame(0x12, ts::str16(reply)), "0x12 mission result");
            break;
        }
        case 0xac: pr.on_mission_fail_stats(r.str()); break;
        case 0x24: {
            pr.on_menu_return();
            // Campaign zones: the game's zone table is read on the game thread; the count
            // "unlocked_zones" is pushed silently when it grew (or once per connection).
            if (m.ctx().host.request_zone_walk) m.ctx().host.request_zone_walk();
            std::string zf = pr.take_zone_push(m.first_menu_return());
            if (!zf.empty()) {
                logi("meta#%d zones: unlocked_zones=%lld -> 0x45 (silent)", m.id(), pr.unlocked_zones());
                m.send_frames(zf, "0x45 unlocked_zones");
            }
            break;
        }
        case 0x16: pr.on_loadout(p); break;
        case 0x17: { unsigned a = r.u8(), b = r.u8(), c = r.u8(); if (r.ok) pr.on_skill(a, b, c); break; }
        case 0x19: { std::uint32_t id = r.u32(), tier = r.u32(); unsigned s = r.u8(); if (r.ok) pr.on_achievement(id, tier, s); break; }
        case 0x1a: pr.on_notification(p); break;
        case 0x32: pr.on_menu_tutorials(p); break;
        case 0xa3: if (!p.empty()) pr.on_difficulty(static_cast<unsigned char>(p[0])); break;
        case 0x53: {
            std::string code = r.str();
            {   // Command codes (cheats, bot match, zones): repeatable, no reward popup.
                std::string what, log;
                std::vector<std::string> frames;
                if (pr.command_code(code, what, log, frames)) {
                    auto& h = m.ctx().host;
                    if (what == "cheats") {
                        Progress::Cheats c = pr.cheats();
                        if (h.apply_cheats) h.apply_cheats(c.god, c.ammo, c.medkits);
                        else log += " (no in-game host: nothing applied)";
                    } else if (what == "botmatch") {
                        std::string why = h.start_bot_match
                            ? h.start_bot_match(static_cast<int>(pr.settings()["bots"]["count"].as_int(6)))
                            : std::string("no in-game host");
                        log += why.empty() ? " -> queued for the game thread" : " -> NOT started: " + why;
                    }
                    logi("meta#%d CODE '%s': %s", m.id(), normalize_code(code).c_str(), log.c_str());
                    for (const auto& f : frames) m.send_frames(f, "0x45 code grant");
                    break;
                }
            }
            RedeemOutcome o = pr.redeem(code);
            logi("meta#%d REDEEM '%s' -> %s: %s (%d items, +%lld credits, +%lld gold, %zu frames, popup %s)",
                 m.id(), o.code.c_str(), o.valid ? "OK" : "INVALID", o.reason.c_str(), o.items, o.credits,
                 o.gold, o.frames.size(), o.reply54.empty() ? "none" : o.reply54.c_str());
            if (!o.valid) {
                // "null" -> CPP_SEND_REDEEM_RESULT_INVALID (no catalog access).
                m.send_frames(ts_frame(0x54, ts::str16("null")), "0x54 null (invalid code)");
                break;
            }
            if (pr.in_mission()) {
                logi("meta#%d redeem during a mission: the grant applies at the next launch", m.id());
                break;
            }
            MetaConn* mp = &m;
            m.spawn([mp, o] { push_grants(*mp, o, true); });
            break;
        }
        case 0x41:
        case 0x42: {
            // Debug-menu cheats and shop purchases. Always answer: the client holds a
            // "tranzaction_in_progress" lock (pm+0x170) until a 0x45 arrives.
            std::string log;
            std::string f = pr.on_purchase(type, p, log);
            logi("meta#%d %s", m.id(), log.c_str());
            m.send_frames(f, "0x45 purchase reply");
            break;
        }
        case 0x48:
            // Item-change claim from the home page (0xc0ebe0: no lock, no reply needed).
            logi("meta#%d 0x48 item-change claim item=%08x sub=%u (no reply needed)", m.id(), be32(p, 0), be32(p, 4));
            break;
        case 0x44: case 0x4d:
            logw("meta#%d purchase frame 0x%02x not served (format not mapped)", m.id(), type);
            break;
        default: break; // 0x74 / 0x69 / 0x50 / 0x34 / 0x66 and the rest: logged above
    }
}

} // namespace

void serve_meta_conn(ServerContext& ctx, Conn& c, const std::string& peer) {
    MetaConn m(ctx, c, peer);
    logi("meta#%d TS/Anubis connection from %s", m.id(), peer.c_str());
    std::string buf;

    // (A) Anubis controller handshake — we greet first, one line per write.
    {
        Json g = Json::object();
        g["action"] = "create connection";
        g["nonce"] = "mc5offline";
        g["success"] = true;
        if (!m.send_line(g)) { m.finish("write failed"); return; }
        m.phase("A:greeted");
    }
    bool connected = false;
    for (int i = 0; i < 16 && !connected; ++i) {
        std::string line;
        if (!read_line(c, buf, line)) { m.finish("closed during controller handshake"); return; }
        if (line.empty()) continue;
        if (!handle_json_line(m, line, connected)) { m.finish("write failed"); return; }
    }
    if (!connected) { logw("meta#%d no 'connect game' within 16 lines", m.id()); m.finish("gave up"); return; }
    m.phase("A:connect-game");

    // (B) TS binary: nothing is written until the client's first frame.
    bool burst_sent = false;
    bool unlock_all_armed = false;
    for (;;) {
        // An unexpected JSON line after "connect game" (the client re-using the
        // controller protocol) — answer it and keep going.
        if (!fill(c, buf, 1)) { m.finish("closed"); return; }
        if (buf[0] == '{') {
            std::string line;
            if (!read_line(c, buf, line)) { m.finish("closed"); return; }
            logw("meta#%d JSON after connect game (unexpected)", m.id());
            bool dummy = false;
            if (!handle_json_line(m, line, dummy)) { m.finish("write failed"); return; }
            continue;
        }
        std::uint8_t type = 0;
        std::string payload;
        if (!read_frame(c, buf, type, payload)) {
            if (!buf.empty() && buf.size() >= 3)
                logw("meta#%d bad TS frame header [%s] — closing", m.id(), hexpre(buf, 16).c_str());
            m.finish("closed");
            return;
        }
        { std::lock_guard<std::mutex> g(ctx.anubis.mu); ++ctx.anubis.frames_in; }
        logi("meta#%d +%ldms ts <- type=0x%02x %s len=%zu [%s]", m.id(), m.ms(), type, ts_name(type),
             payload.size(), hexpre(payload).c_str());
        if (payload.size() > 48) log_full_payload(m, type, payload);

        if (!burst_sent) {
            std::string country;
            unsigned gate5a = 0;
            if (type == 0x01) {
                std::string d = decode_init_settings(payload);
                logi("meta#%d InitSettings: %s", m.id(), d.c_str());
                init_fields(payload, country, gate5a);
                std::lock_guard<std::mutex> g(ctx.anubis.mu);
                ctx.anubis.init_settings = d;
            } else {
                logw("meta#%d first TS frame is 0x%02x, expected 0x01 — sending the burst anyway", m.id(), type);
            }
            ctx.progress.on_init_settings(country, gate5a);
            m.phase("B:first-frame");
            std::string why;
            std::string prof = ctx.progress.login_profile_frame(gate5a, why);
            const bool game_cfg = ctx.progress.settings()["config"]["sendGame"].as_bool(true);
            const std::string cfg = game_cfg ? config_json() : std::string("{}");
            logi("meta#%d login: TCP_Config %s; TCP_Profile %s (%s)", m.id(), cfg.c_str(),
                 prof.empty() ? "not sent" : "SENT", why.c_str());
            if (!m.send_frames(login_burst(cfg, prof),
                               prof.empty() ? "login burst 0x22+0x3e+0x04+0x4a"
                                            : "login burst 0x22+0x3e+PROFILE+0x04+0x4a",
                               prof.empty() ? 4 : 5)) { m.finish("write failed"); return; }
            ctx.progress.on_reset_b0();
            burst_sent = true;
            m.phase(prof.empty() ? "B:burst-sent" : "B:burst+profile-sent");
            m.start_keepalive();
            if (type == 0x01) continue; // the 0x49 that follows is answered below
        }

        log_milestone(m, type, payload);
        ctx.progress.after_login_frame(type);
        handle_frame(m, type, payload);

        // settings.unlockAll: once the menu is up (first 0x24/0x34), after a delay.
        if (!unlock_all_armed && (type == 0x24 || type == 0x34) && ctx.progress.unlock_all_pending()) {
            unlock_all_armed = true;
            long delay = static_cast<long>(
                ctx.progress.settings()["unlocks"]["startDelaySeconds"].as_int(10)) * 1000;
            MetaConn* mp = &m;
            m.spawn([mp, delay] {
                if (!mp->wait_ms(delay)) return;
                if (mp->ctx().progress.in_mission()) {
                    logi("meta#%d unlockAll: in a mission; it applies at the next launch", mp->id());
                    return;
                }
                RedeemOutcome o = mp->ctx().progress.unlock_all_once();
                logi("meta#%d unlockAll: %s (%d items, %zu frames)", mp->id(), o.reason.c_str(), o.items,
                     o.frames.size());
                push_grants(*mp, o);
            });
        }
    }
}

} // namespace mc5
