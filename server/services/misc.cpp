// Core status routes (for us, not the game) and the catch-all.
//
// The catch-all logs every unmatched request in full so device testing reveals
// exactly what the client needs next. It answers conservatively and never returns
// 403/404: on Gaia a 403 is treated as upgrade-required or wipes the profile, and
// a 404 aborts the request. Unknown endpoints therefore get a 200 with an empty
// JSON object (refined per-endpoint as the device log shows their real shape).

#include "services.hpp"

#include <ctime>

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {
std::time_t g_start = std::time(nullptr);
}

void register_core(Router& router, ServerContext& ctx) {
    // eve probes GET / to see if the environment is up.
    router.add("GET", "", [](const Request&) { return Response::json("{}"); });

    router.add("GET", "_mc5/status", [&ctx](const Request&) {
        Json o = Json::object();
        o["name"] = "mc5-offline";
        o["client_id"] = ctx.client_id;
        o["data_center"] = ctx.data_center;
        o["base_url"] = ctx.base_url();
        o["uptime_seconds"] = static_cast<long long>(std::time(nullptr) - g_start);
        return Response::json(o.dump());
    });

    router.add("GET", "_mc5/routes", [&router](const Request&) {
        Json arr = Json::array();
        for (const auto& r : router.routes()) arr.push_back(r);
        return Response::json(arr.dump());
    });

    // Phone-readable copy of the recent log (the owner's uploads arrive as 0 bytes;
    // this is viewable over loopback/adb instead).
    router.add("GET", "_mc5/log", [](const Request& req) {
        std::size_t n = 500;
        std::string q = req.value("n");
        if (!q.empty()) { try { n = static_cast<std::size_t>(std::stoul(q)); } catch (...) {} }
        std::string out;
        for (const auto& line : Log::instance().tail(n)) { out += line; out += '\n'; }
        return Response::text(out);
    });
}

void register_misc(Router& router, ServerContext&) {
    router.set_fallback([](const Request& req) {
        std::string hdrs;
        for (const auto& h : req.headers) hdrs += h.first + "=" + h.second + " ";
        logw("UNKNOWN %s %s | headers: %s| body(%zu): %.400s",
             req.method.c_str(), req.raw_target.c_str(), hdrs.c_str(), req.body.size(), req.body.c_str());
        return Response::json("{}", 200);
    });
}

} // namespace mc5
