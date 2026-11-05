// matchmaker / Federation sessions: how the client finds the Anubis controller (the
// TCP socket that then carries the TS meta-channel). Two client paths, chosen in the
// Anubis FSM state 3 (0xc07340) by a process-sticky mode flag (global 0x1bc586c):
//
//   Mode 0 (primary — eve serves "federation"):
//     POST <federation>/sessions/<urlenc client_id>/<urlenc credential>
//          body password=..&device_id=..            (request type 0x1902)
//     -> 200 {"controller_host":str,"controller_tcp_port":NUMBER,
//             "encrypted_access_token":str (non-empty),"room_id":str}
//     State 4 (0xc07780) needs all four; jsoncpp asInt (0x1053a30) gives 0 for a
//     string port. "{}" (our old catch-all reply) -> Anubis error "awri" -> login
//     error "glawri". Any non-2xx status flips the process to mode 1 for good.
//
//   Mode 1 (fallback — federation missing, or after one mode-0 failure):
//     POST <matchmaker>/rooms/<clientId>/automatch/quick_join_ah
//          body access_token=..&filter=ahgameserver&isolated=true&midgame_join=true
//               &server_type=ts                    (request type 0x1580)
//     -> a room object (or an array whose first element is one), parsed by 0xc3c060:
//        room_id|id (str), controller_host (str), controller_port (NUMBER — note the
//        name), creator_datacenter (str, optional, top level).
//     Mode 1 additionally needs a Gaia nonce->token exchange (0xc8fab8) whose
//     endpoint is not mapped yet, so it is defence in depth only.
//
// The controller host/port point at our own loopback listener (the connect() hook
// maps the port anyway); server.cpp hands the quiet socket to meta.cpp.
// See docs/research/02-post-auth-chain.md §15.

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {

const char* kRoomId = "mc5offline-ts";

std::string cut(const std::string& s, std::size_t n = 8) {
    return s.size() <= n ? s : s.substr(0, n) + "..";
}

Response quick_join(ServerContext& ctx, const Request& req) {
    // Multiplayer Quick Play (automatch quickplayany / quickplaynewplayer /
    // quickplayzombie) wanted Gameloft's dedicated game servers: a joined client is never
    // the match authority (0x8cd650 clears conn+0x6c), so it cannot run bots. Answer "no
    // room" quickly (the client shows its own error) instead of handing out our TS
    // controller, which only made the client open a second TS socket and time out.
    // Offline bot matches are started locally instead (redeem code BOTMATCH).
    const std::string am = req.param("automatcher");
    if (am.compare(0, 9, "quickplay") == 0) {
        logi("matchmaker: Quick Play '%s' filter='%s' server_type='%s' -> [] (offline: use the BOTMATCH code "
             "for a local bot match)", am.c_str(), req.value("filter").c_str(), req.value("server_type").c_str());
        return Response::json("[]");
    }
    int n;
    {
        std::lock_guard<std::mutex> g(ctx.anubis.mu);
        n = ++ctx.anubis.quick_joins;
        ctx.anubis.room = kRoomId;
    }
    logw("matchmaker: %s %s (Anubis MODE 1 — process-sticky; restart the app after fixing mode 0) "
         "#%d server_type='%s' filter='%s' isolated='%s' midgame_join='%s' access_token='%s' -> %s:%d",
         req.method.c_str(), req.path.c_str(), n, req.value("server_type").c_str(),
         req.value("filter").c_str(), req.value("isolated").c_str(),
         req.value("midgame_join").c_str(), cut(req.value("access_token")).c_str(),
         ctx.public_host.c_str(), ctx.port);

    Json o = Json::object();
    o["room_id"] = kRoomId;
    o["controller_host"] = ctx.public_host;   // 127.0.0.1
    o["controller_port"] = ctx.port;          // NUMBER; the name 0xc3c060 reads
    o["creator_datacenter"] = ctx.data_center;
    // Harmless extras (end up as room custom attributes).
    o["controller_tcp_port"] = ctx.port;
    o["encrypted_access_token"] = "mc5o-anubis-mm";
    return Response::json(o.dump());
}

} // namespace

Response federation_session(ServerContext& ctx, const Request& req) {
    // Form: parsed body, or re-parse the raw body if the header was missing.
    std::map<std::string, std::string> form = req.form;
    if (form.empty() && !req.body.empty()) form = parse_urlencoded(req.body);
    std::string device_id = form.count("device_id") ? form["device_id"] : req.value("device_id");
    std::size_t pw_len = form.count("password") ? form["password"].size() : 0;

    int n;
    std::string token;
    {
        std::lock_guard<std::mutex> g(ctx.anubis.mu);
        n = ++ctx.anubis.sessions;
        token = "mc5o-anubis-" + std::to_string(n);
        ctx.anubis.token = token;
        ctx.anubis.room = kRoomId;
    }

    Json o = Json::object();
    o["controller_host"] = ctx.public_host;
    o["controller_tcp_port"] = ctx.port;      // NUMBER (asInt gives 0 for a string)
    o["encrypted_access_token"] = token;      // non-empty, echoed back as access_token
    o["room_id"] = kRoomId;
    std::string body = o.dump();
    logi("anubis: federation session #%d (mode 0) client_id='%s' credential='%s' device_id='%s' "
         "password_len=%zu -> %s",
         n, req.param("clientId").c_str(), cut(req.param("credential"), 24).c_str(),
         device_id.c_str(), pw_len, body.c_str());
    return Response::json(body);
}

void register_matchmaker(Router& router, ServerContext& ctx) {
    // Mode 0: Federation sessions (the eve "federation" prefix is stripped by the
    // router; the credential may decode to text containing '/', hence the tail).
    router.add("POST", "sessions/{clientId}/{*credential}",
               [&ctx](const Request& r) { return federation_session(ctx, r); });

    // Mode 1: matchmaker automatch (specific route before the rooms catch-all).
    auto h = [&ctx](const Request& r) { return quick_join(ctx, r); };
    router.add("POST", "rooms/{clientId}/automatch/{automatcher}", h);
    router.add("POST", "rooms/{clientId}/quick_join_ah", h);
    router.add("GET", "rooms/{clientId}/quick_join_ah", h);
    router.add("POST", "rooms/{clientId}/quick_join", h);
    router.add("POST", "rooms/{clientId}/automatch", h);
    router.add("POST", "rooms/{clientId}/{*rest}", h);
    router.add("GET", "rooms/{clientId}/{*rest}", h);
}

} // namespace mc5
