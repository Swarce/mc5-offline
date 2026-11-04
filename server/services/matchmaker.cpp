// matchmaker: the client joins a room to reach a server. For server_type="ts" the
// response locates the transaction server (TS) — the Anubis controller socket that
// then carries the TS meta-channel (profile/economy). We point it at our own
// loopback listener; the connect() hook rewrites the port to ours anyway, and our
// listener multiplexes HTTP vs the Anubis/TS protocol (see server.cpp + meta.cpp).
//
//   POST matchmaker/rooms/{clientId}/quick_join_ah  (server_type=ts)
//     -> {room_id, controller_host, controller_tcp_port, encrypted_access_token}
//
// server_type="ahgameserver" is the in-match game/relay server (M2); we answer it
// the same way for now and log it.

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {

Response quick_join(ServerContext& ctx, const Request& req) {
    std::string server_type = req.value("server_type");
    std::string token = req.value("access_token");
    logi("matchmaker: quick_join server_type='%s' -> TS at %s:%d", server_type.c_str(),
         ctx.public_host.c_str(), ctx.port);

    Json o = Json::object();
    o["room_id"] = server_type.empty() ? std::string("ts") : server_type;
    o["controller_host"] = ctx.public_host;   // 127.0.0.1
    o["controller_tcp_port"] = ctx.port;       // our listener; connect() hook maps it here anyway
    o["host"] = ctx.public_host;
    o["port"] = ctx.port;
    o["encrypted_access_token"] = token.empty() ? std::string("mc5offline") : token;
    o["status"] = "ok";
    o["result"] = 0;
    return Response::json(o.dump());
}

} // namespace

void register_matchmaker(Router& router, ServerContext& ctx) {
    auto h = [&ctx](const Request& r) { return quick_join(ctx, r); };
    router.add("POST", "rooms/{clientId}/quick_join_ah", h);
    router.add("GET", "rooms/{clientId}/quick_join_ah", h);
    router.add("POST", "rooms/{clientId}/quick_join", h);
    router.add("POST", "rooms/{clientId}/automatch", h);
    router.add("POST", "rooms/{clientId}/{*rest}", h);
    router.add("GET", "rooms/{clientId}/{*rest}", h);
}

} // namespace mc5
