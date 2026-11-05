// Anubis / TS meta-channel contract test: drives the server the way libMC5 6.0.12a
// does (docs/research/02-post-auth-chain.md §15) — eve urls carries game_portal, the
// mode-0 Federation sessions POST returns the four controller keys (numeric port),
// and the controller socket greets first, answers "connect game", stays silent until
// the client's first TS frame, then sends the 29-byte gate burst and keepalives.
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>
#include <thread>

#include "../server/core/json.hpp"
#include "../server/core/server.hpp"
#include "../server/services/services.hpp"
#include "check.hpp"

using namespace mc5;

namespace {

class SockConn : public Conn {
public:
    explicit SockConn(int fd) : fd_(fd) {}
    ~SockConn() override { close(); }
    long read(char* b, std::size_t n) override { return ::recv(fd_, b, n, 0); }
    long write(const char* b, std::size_t n) override { return ::send(fd_, b, n, MSG_NOSIGNAL); }
    void close() override { if (fd_ >= 0) { ::close(fd_); fd_ = -1; } }
private:
    int fd_;
};

bool read_exact(int fd, std::string& out, std::size_t n) {
    out.clear();
    char b[256];
    while (out.size() < n) {
        long r = ::recv(fd, b, std::min(sizeof(b), n - out.size()), 0);
        if (r <= 0) return false;
        out.append(b, static_cast<std::size_t>(r));
    }
    return true;
}

bool read_line(int fd, std::string& line) {
    line.clear();
    char ch;
    while (::recv(fd, &ch, 1, 0) == 1) {
        if (ch == '\n') return true;
        line.push_back(ch);
    }
    return false;
}

void set_timeout(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

std::string frame(unsigned char type, const std::string& payload) {
    std::string o(1, static_cast<char>(type));
    std::size_t n = payload.size() + 3;
    o.push_back(static_cast<char>(n >> 8));
    o.push_back(static_cast<char>(n & 0xff));
    return o + payload;
}

std::string str16(const std::string& s) {
    std::string o;
    o.push_back(static_cast<char>(s.size() >> 8));
    o.push_back(static_cast<char>(s.size() & 0xff));
    return o + s;
}

std::string read_all(int fd) {
    std::string out;
    char b[512];
    long r;
    while ((r = ::recv(fd, b, sizeof(b), 0)) > 0) out.append(b, static_cast<std::size_t>(r));
    return out;
}

std::string hex(const std::string& s) {
    static const char* H = "0123456789abcdef";
    std::string o;
    for (unsigned char c : s) { o.push_back(H[c >> 4]); o.push_back(H[c & 15]); }
    return o;
}

} // namespace

int main() {
    ServerContext ctx;
    ctx.scheme = "https";
    Router router;
    register_services(router, ctx);

    // eve urls: game_portal is a non-empty string, no trailing slash; federation kept.
    {
        Request r;
        r.method = "GET";
        r.path = "/config/" + ctx.client_id + "/datacenters/eur/urls";
        Json j;
        CHECK(Json::try_parse(router.route(r).body, j));
        CHECK(j["game_portal"].is_string());
        CHECK_EQ(j["game_portal"].as_string(), ctx.base_url() + "game_portal");
        CHECK(j["federation"].is_string());
        CHECK_EQ(j["status"].as_string(), std::string("none"));
    }

    // Mode 0: POST <federation>/sessions/<cid>/<cred>, form body password&device_id.
    std::string token;
    {
        Request r;
        r.method = "POST";
        r.path = "/federation//sessions/" + ctx.client_id + "/anonymous:abc/def";
        r.body = "password=secret&device_id=dev-1";
        r.form = parse_urlencoded(r.body);
        Response resp = router.route(r);
        Json j;
        CHECK_EQ(resp.status, 200);
        CHECK(Json::try_parse(resp.body, j));
        CHECK(j["controller_host"].is_string());
        CHECK(j["controller_tcp_port"].is_number());
        CHECK_EQ(j["controller_tcp_port"].as_int(), ctx.port);
        CHECK(j["room_id"].is_string());
        CHECK(j["encrypted_access_token"].is_string());
        token = j["encrypted_access_token"].as_string();
        CHECK(!token.empty());
    }
    // Same request without the content-type (raw body only) still answers.
    {
        Request r;
        r.method = "POST";
        r.path = "/federation/sessions/" + ctx.client_id + "/cred";
        r.body = "password=x&device_id=dev-2";
        Json j;
        CHECK(Json::try_parse(router.route(r).body, j));
        CHECK(j["controller_tcp_port"].is_number());
    }
    // Mode 1: rooms/<cid>/automatch/quick_join_ah -> controller_port as a number.
    {
        Request r;
        r.method = "POST";
        r.path = "/matchmaker/rooms/" + ctx.client_id + "/automatch/quick_join_ah";
        r.body = "access_token=t&filter=ahgameserver&isolated=true&midgame_join=true&server_type=ts";
        r.form = parse_urlencoded(r.body);
        Json j;
        CHECK(Json::try_parse(router.route(r).body, j));
        CHECK(j["controller_port"].is_number());
        CHECK(j["room_id"].is_string());
        CHECK(j["controller_host"].is_string());
    }

    // compliancy.json: legislation + the five <GameType> sections, each mapping both
    // legislation keys to an object whose members are all EMPTY arrays (never [{}]).
    {
        Request r;
        r.method = "GET";
        r.path = "/asset/assets/" + ctx.client_id + "/compliancy.json";
        Response resp = router.route(r);
        CHECK_EQ(resp.status, 200);
        Json j;
        CHECK(Json::try_parse(resp.body, j));
        CHECK(j["LegislationTypes"].is_array());
        CHECK(j["RestOfTheWorld"].is_array());
        for (const char* gt : {"Adult_Games_ads_on", "Adult_Games_ads_off", "Mixt_Standard", "Mixt_Plus", "Kids"}) {
            CHECK(j[gt].is_object());
            for (const char* leg : {"RestOfTheWorld", "RotW"}) {
                CHECK(j[gt][leg].is_object());
                CHECK(j[gt][leg]["none"].is_array());
                CHECK_EQ(j[gt][leg]["none"].size(), static_cast<std::size_t>(0));
            }
        }
        CHECK(resp.body.find("{}]") == std::string::npos);  // no empty condition object
    }
    // Absent assets: 404, empty body; behavioral still served.
    for (const char* m : {"GET", "HEAD"}) {
        for (std::string tail : {"/GameOptions", "/use_custom_param", "/events_HD_UPD18",
                                 "/videos_HD_UPD18/metadata", "/events_HD_UPD18/metadata/hash"}) {
            Request r;
            r.method = m;
            r.path = "/asset//assets/" + ctx.client_id + tail;
            Response resp = router.route(r);
            CHECK_EQ(resp.status, 404);
            CHECK(resp.body.empty());
        }
    }
    {
        Request r;
        r.method = "GET";
        r.path = "/asset//assets/" + ctx.client_id + "/behavioral.json";
        CHECK_EQ(router.route(r).status, 200);
    }
    // Storage consent: 200 "{}".
    {
        Request r;
        r.method = "POST";
        r.path = "/storage//profiles/me/myprofile/consent";
        r.body = "access_token=t&consent=%7B%22explicit%22%3Atrue%7D&operation=set";
        r.form = parse_urlencoded(r.body);
        Response resp = router.route(r);
        CHECK_EQ(resp.status, 200);
        CHECK_EQ(resp.body, std::string("{}"));
    }
    // HTTP state machine: HEAD gets headers only, so a kept-alive GET right after it
    // still parses cleanly.
    {
        ServerConfig cfg;
        cfg.port = 0;  // ephemeral; start() only so serve_conn's running flag is set
        Server srv(cfg);
        register_services(srv.router(), ctx);
        CHECK(srv.start());
        int hp[2];
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, hp) == 0);
        std::thread t([&] { SockConn c(hp[0]); srv.serve_conn(c, "test"); });
        std::string reqs = "HEAD /asset//assets/" + ctx.client_id + "/GameOptions HTTP/1.1\r\nHost: x\r\n\r\n"
                           "GET /asset/assets/" + ctx.client_id + "/behavioral.json HTTP/1.1\r\nHost: x\r\n"
                           "Connection: close\r\n\r\n";
        CHECK(::send(hp[1], reqs.data(), reqs.size(), 0) == static_cast<long>(reqs.size()));
        set_timeout(hp[1], 3000);
        std::string all = read_all(hp[1]);
        ::close(hp[1]);
        t.join();
        CHECK(all.rfind("HTTP/1.1 404", 0) == 0);
        std::size_t second = all.find("HTTP/1.1 200");
        CHECK(second != std::string::npos);
        // Nothing between the HEAD headers' blank line and the next status line.
        std::size_t head_end = all.find("\r\n\r\n");
        CHECK(head_end != std::string::npos && head_end + 4 == second);
        CHECK(all.find("rules", second) != std::string::npos);
        srv.stop();
    }

    // Controller + TS channel over a socketpair.
    int sv[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    std::thread srv([&] {
        SockConn c(sv[0]);
        serve_meta_conn(ctx, c, "test");
    });
    int cl = sv[1];
    set_timeout(cl, 3000);

    std::string line;
    CHECK(read_line(cl, line));
    Json greet;
    CHECK(Json::try_parse(line, greet));
    CHECK_EQ(greet["action"].as_string(), std::string("create connection"));
    CHECK(greet["nonce"].is_string());
    CHECK(greet["success"].as_bool());

    std::string cg = "{\"access_token\":\"" + token +
                     "\",\"action\":\"connect game\",\"nonce_type\":\"targeted\","
                     "\"room_id\":\"mc5offline-ts\",\"username\":\"anonymous:x\"}\n";
    CHECK(::send(cl, cg.data(), cg.size(), 0) == static_cast<long>(cg.size()));
    CHECK(read_line(cl, line));
    Json rep;
    CHECK(Json::try_parse(line, rep));
    CHECK_EQ(rep["action"].as_string(), std::string("connect game"));
    CHECK(rep["slot"].is_string());
    CHECK(rep["success"].as_bool());

    // Nothing may arrive before the client's first TS frame.
    {
        set_timeout(cl, 300);
        char b;
        CHECK(::recv(cl, &b, 1, 0) < 0);
        set_timeout(cl, 3000);
    }

    // Client: 0x01 InitSettings then 0x49.
    std::string init;
    init += '\x33';
    init += '\x0b';
    init += std::string("\x00\x00\x00\x01", 4);
    for (const char* s : {"id", "en", "1924:56128:6.0.12a:android:googleplay",
                          "http://127.0.0.1:51780/game_portal/1/190/private/OfficialScripts/mc5Portal.wsgi",
                          "https://127.0.0.1:51780/pandora/"})
        init += str16(s);
    init += '\x00';
    for (const char* s : {"dev", "a", "b", "igp"}) init += str16(s);
    init += '\x01';
    init += '\x00';
    init += std::string("\x00\x00\x4e\x20", 4);
    std::string out = frame(0x01, init) + frame(0x49, "");
    CHECK(::send(cl, out.data(), out.size(), 0) == static_cast<long>(out.size()));

    std::string burst;
    CHECK(read_exact(cl, burst, 29));
    CHECK_EQ(hex(burst), std::string("220003"
                                     "3e000900000002" "7b7d"
                                     "04000a00" "00000002" "5b5d"
                                     "4a000700000000"));
    std::string r4a;
    CHECK(read_exact(cl, r4a, 7));
    CHECK_EQ(hex(r4a), std::string("4a000700000000"));

    // 0x96 -> 0x22 again.
    std::string f96 = frame(0x96, "");
    CHECK(::send(cl, f96.data(), f96.size(), 0) == 3);
    std::string r22;
    CHECK(read_exact(cl, r22, 3));
    CHECK_EQ(hex(r22), std::string("220003"));

    // Keepalive within ~5 s.
    set_timeout(cl, 7000);
    std::string ka;
    CHECK(read_exact(cl, ka, 3));
    CHECK_EQ(hex(ka), std::string("020003"));

    // Post-login client frames are fire-and-forget: the server must not answer them.
    {
        std::string tr = str16("true");
        std::string post = frame(0x50, std::string("\x00\x00\x00\x02\x00\x00\x00\x00", 8)) +
                           frame(0x0b, str16("{\"display_name\":\"SOLDIER_1\"}\n")) +
                           frame(0x34, "") + frame(0x52, "") + frame(0xad, tr + tr + tr) +
                           frame(0xa8, "") + frame(0x59, std::string("\x00\x00\x00\x1e\x00\x00\x00\x01", 8));
        CHECK(::send(cl, post.data(), post.size(), 0) == static_cast<long>(post.size()));
        set_timeout(cl, 400);
        char b;
        CHECK(::recv(cl, &b, 1, 0) < 0);
        // ...and the link is still alive: 0x96 is still answered.
        set_timeout(cl, 3000);
        CHECK(::send(cl, f96.data(), f96.size(), 0) == 3);
        std::string again;
        CHECK(read_exact(cl, again, 3));
        CHECK_EQ(hex(again), std::string("220003"));
    }

    ::shutdown(cl, SHUT_RDWR);
    ::close(cl);
    srv.join();

    {
        std::lock_guard<std::mutex> g(ctx.anubis.mu);
        CHECK_EQ(ctx.anubis.phase, std::string("B:burst-sent"));
        CHECK(ctx.anubis.init_settings.find("portal='http://127.0.0.1:51780/game_portal/") != std::string::npos);
        CHECK(ctx.anubis.init_settings.find("TRUNC") == std::string::npos);
        CHECK(ctx.anubis.keepalives >= 1);
    }
    return mc5test::failures();
}
