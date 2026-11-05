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
//       Then one 29-byte burst sets the four flags state 10 (0xc07740) waits for:
//         22 00 03                          -> +0xb0, +0xb2           (0xc09da4)
//         3e 00 09 | blob32 "{}"            -> +0xb3 TCP_Config plain (0xc0b1a8)
//         04 00 0a | u8 0 | blob32 "[]"     -> event 2 -> +0xb1 (TCP_Tournaments,
//                                              main-thread pump 0xc05e50 -> 0xc05850)
//         4a 00 07 | u32 0                  -> +0x83, +0xb4           (0xc0adf8)
//       After that, the TS idle watchdog (0xc0bcb8) drops the link after 15 s of
//       silence, so we send the no-op frame 02 00 03 every 5 s (type 2 hits the
//       handler's default case 0xc0b5a4; the prologue refreshes +0x3c for every
//       frame) and never close the socket ourselves.
//
// NEVER send: 0x3a (integrity), 0x20 (switches to the 180 s/atsv path), 0x33,
// 0x0d/0x3c with JSON (kick/ban), a 0x3e/0x3f payload of exactly "ERR". A
// TCP_Profile (0x03 / 0x27) is not needed for the gate and stays off until its
// loaders are verified (env MC5_TS_PROFILE=1 enables it for experiments).
// See docs/research/02-post-auth-chain.md §15 and docs/protocol/tcp-messages.md.

#include "services.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

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
[[maybe_unused]] std::string lz4_store(const std::string& data) {
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
[[maybe_unused]] std::string lz4blob(const std::string& data) {
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

std::string jstr(const Json& j, const char* k) {
    const Json& v = j[k];
    return v.is_string() ? v.as_string() : std::string();
}

// Bounds-checked big-endian reader for client TS payloads.
struct BeReader {
    const std::string& d;
    std::size_t p = 0;
    bool ok = true;
    explicit BeReader(const std::string& s) : d(s) {}
    bool need(std::size_t n) { if (!ok || p + n > d.size()) ok = false; return ok; }
    unsigned u8() { if (!need(1)) return 0; return static_cast<unsigned char>(d[p++]); }
    unsigned long u32() {
        if (!need(4)) return 0;
        unsigned long v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | static_cast<unsigned char>(d[p++]);
        return v;
    }
    std::string str() {
        if (!need(2)) return std::string();
        std::size_t n = (static_cast<unsigned char>(d[p]) << 8) | static_cast<unsigned char>(d[p + 1]);
        p += 2;
        if (!need(n)) return std::string();
        std::string s = d.substr(p, n);
        p += n;
        return s;
    }
};

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

// The 29-byte gate burst (see header).
std::string gate_burst() {
    std::string o;
    o += ts_frame(0x22, "");                                      // b0, b2
    o += ts_frame(0x3e, blob32("{}"));                            // b3 (TCP_Config, plain)
    o += ts_frame(0x04, std::string(1, '\0') + blob32("[]"));     // b1 (TCP_Tournaments)
    o += ts_frame(0x4a, std::string(4, '\0'));                    // b4 (u32 n=0)
    return o;
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
    }

    void finish(const char* why) {
        stop_keepalive();
        logi("meta#%d %s %s after %ldms, last phase '%s'", id_, peer_.c_str(), why, ms(), phase_.c_str());
        c_.close();
    }

    ServerContext& ctx() { return ctx_; }

private:
    ServerContext& ctx_;
    Conn& c_;
    std::string peer_;
    int id_;
    std::chrono::steady_clock::time_point t0_;
    std::string phase_ = "accepted";
    std::mutex wmu_;
    std::thread ka_;
    std::mutex cvm_;
    std::condition_variable cv_;
    bool stop_ = false;
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
    static const char* H = "0123456789abcdef";
    std::string out;
    for (unsigned char b : p) {
        if (b >= 0x20 && b < 0x7f && b != '\\') out.push_back(static_cast<char>(b));
        else if (b == '\n') out += "\\n";
        else { out += "\\x"; out.push_back(H[b >> 4]); out.push_back(H[b & 0xf]); }
    }
    const std::size_t kChunk = 800;
    std::size_t parts = (out.size() + kChunk - 1) / kChunk;
    for (std::size_t i = 0; i < parts; ++i)
        logi("meta#%d ts-full 0x%02x len=%zu part %zu/%zu: %s", m.id(), type, p.size(), i + 1, parts,
             out.substr(i * kChunk, kChunk).c_str());
}

const char* ts_name(std::uint8_t t) {
    // Client->server meta frames (docs/research/02 §17). None of the post-login ones
    // expects a reply: each builder only serialises + sends (verified per builder).
    switch (t) {
        case 0x01: return "ClientSendInitSettings";
        case 0x05: return "login-cred(alt)";
        case 0x0b: return "public-info";
        case 0x16: return "ack-0x22";
        case 0x21: return "profile-wait-timeout";
        case 0x34: return "tournaments-refresh";
        case 0x49: return "request-0x4a";
        case 0x50: return "login-cred";
        case 0x52: return "app-resume";
        case 0x59: return "age-gender (AGE GATE OK)";
        case 0x5a: return "geo";
        case 0x69: return "0x69";
        case 0x74: return "profile-ack";
        case 0x96: return "reset-b0";
        case 0xa8: return "restrictions-ok";
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
    const bool with_profile = [] { const char* e = std::getenv("MC5_TS_PROFILE"); return e && e[0] == '1'; }();
    bool burst_sent = false;
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
            if (type == 0x01) {
                std::string d = decode_init_settings(payload);
                logi("meta#%d InitSettings: %s", m.id(), d.c_str());
                std::lock_guard<std::mutex> g(ctx.anubis.mu);
                ctx.anubis.init_settings = d;
            } else {
                logw("meta#%d first TS frame is 0x%02x, expected 0x01 — sending the burst anyway", m.id(), type);
            }
            m.phase("B:first-frame");
            if (!m.send_frames(gate_burst(), "gate burst 0x22+0x3e+0x04+0x4a", 4)) { m.finish("write failed"); return; }
            burst_sent = true;
            m.phase("B:burst-sent");
            if (with_profile) {
                std::string prof = ts_frame(0x03, blob32(default_profile(ctx)));
                if (prof.size() <= 0xFFFF) m.send_frames(prof, "0x03 TCP_Profile (MC5_TS_PROFILE=1)");
                else logw("meta#%d profile frame too large (%zu B) — not sent", m.id(), prof.size());
            }
            m.start_keepalive();
            if (type == 0x01) continue; // the 0x49 that follows is answered below
        }

        log_milestone(m, type, payload);
        switch (type) {
            case 0x49: m.send_frames(ts_frame(0x4a, std::string(4, '\0')), "0x4a (reply to 0x49)"); break;
            case 0x96: m.send_frames(ts_frame(0x22, ""), "0x22 (reply to 0x96, restores b0)"); break;
            case 0x21: logw("meta#%d client reports a profile-wait timeout (0x21)", m.id()); break;
            default: break; // 0x16 / 0x74 / 0x69 and the rest: logged above
        }
    }
}

} // namespace mc5
