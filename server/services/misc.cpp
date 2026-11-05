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
        {
            std::lock_guard<std::mutex> g(ctx.anubis.mu);
            Json a = Json::object();
            a["sessions"] = ctx.anubis.sessions;
            a["quick_joins"] = ctx.anubis.quick_joins;
            a["conns"] = ctx.anubis.conns;
            a["token"] = ctx.anubis.token;
            a["room"] = ctx.anubis.room;
            a["phase"] = ctx.anubis.phase;
            a["mode"] = ctx.anubis.mode;
            a["frames_in"] = static_cast<long long>(ctx.anubis.frames_in);
            a["frames_out"] = static_cast<long long>(ctx.anubis.frames_out);
            a["keepalives"] = static_cast<long long>(ctx.anubis.keepalives);
            a["init_settings"] = ctx.anubis.init_settings;
            o["anubis"] = std::move(a);
        }
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

void register_misc(Router& router, ServerContext& ctx) {
    router.set_fallback([&ctx](const Request& req) {
        // Anubis mode 0 safety net: if the Federation-sessions POST arrives on a path
        // the route did not match (its base URL resolution was not traced end to
        // end), answer it properly — a "{}" here fails with "glawri" and any non-2xx
        // flips the client to mode 1 for the rest of the process.
        bool sessionsish = req.path.find("/sessions/") != std::string::npos;
        if (req.method == "POST" && sessionsish &&
            (req.form.count("device_id") || req.body.find("device_id=") != std::string::npos)) {
            logw("anubis: WARN federation sessions via fallback (%s) — route did not match", req.path.c_str());
            return federation_session(ctx, req);
        }
        const char* tag = (sessionsish || req.path.find("automatch") != std::string::npos ||
                           req.path.find("nonce") != std::string::npos) ? "ANUBIS? " : "";
        std::string hdrs;
        for (const auto& h : req.headers) hdrs += h.first + "=" + h.second + " ";
        logw("%sUNKNOWN %s %s | headers: %s| body(%zu): %.400s",
             tag, req.method.c_str(), req.raw_target.c_str(), hdrs.c_str(), req.body.size(), req.body.c_str());
        return Response::json("{}", 200);
    });
}

} // namespace mc5
