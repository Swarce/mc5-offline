// eve: the environment switcher. The client's first call. It asks for the list of
// datacenters, picks the active+preferred one, then asks that datacenter for its
// service URLs.
//
// Shapes mirror the known-good MCVS Offline eve contract (same Gaia SDK), confirmed
// against this client on device (Nov 2026):
//
//   GET config/{clientId}/datacenters
//     -> [{"name":<dc>,"status":"active","preferred":true,"country_code":"US"}]
//        The client takes the first entry with preferred=true; the name must be
//        non-empty ("Incorrect datacenter" otherwise).
//
//   GET config/{clientId}/datacenters/{dc}/urls
//     -> {"pandora":...,"game_portal":...,"ecomm_api_root":...,"crm_iap":..., ...}
//        A JSON object of service -> URL, each <base><service>/. NO "status" key
//        (any value shows an update/maintenance popup, an unknown one throws).
//        pandora is required for every fed service; ecomm_api_root and crm_iap are
//        located by IapStoreComponent.InitNative, which THROWS without them (this
//        was the on-device boot loop: a urls object with only pandora made IAP init
//        fail, so the client never advanced to pandora). Answered for any dc name
//        (a client that played online before may have Gameloft's datacenter saved).

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {
// The full service map. MCVS's C# client reads only the non-fed services here and
// locates fed services via pandora, but MC5's Gaia is fully native and the native
// init may expect every service URL straight from eve config; a superset is safe
// (every key just becomes Services[key]=url) and avoids the init stalling before
// it reaches pandora/auth. Union of fed + eve + native services (+ federation).
const char* kEveServices[] = {
    // fed services (also locatable via pandora)
    "auth", "storage", "leaderboard", "alert", "config", "groupchat", "lobby",
    "matchmaker", "message", "social", "asset", "game_stats",
    // eve-served (non-fed)
    "pandora", "federation", "game_portal", "ads_agency", "marketing_site",
    "ecomm_api_root", "crm_iap", "etsv2",
    // native-only services
    "feeds", "lottery", "voice", "schedule", "globalidservice", "transaction",
};
} // namespace

void register_eve(Router& router, ServerContext& ctx) {
    router.add("GET", "config/{clientId}/datacenters", [&ctx](const Request& req) {
        std::string country = req.value("country");
        if (country.empty()) country = "US";
        Json arr = Json::array();
        Json dc = Json::object();
        dc["name"] = ctx.data_center;
        dc["status"] = "active";
        dc["preferred"] = true;
        dc["country_code"] = country;
        arr.push_back(std::move(dc));
        return Response::json(arr.dump());
    });

    router.add("GET", "config/{clientId}/datacenters/{dc}/urls", [&ctx](const Request&) {
        // One object of service -> "<base><service>/". No "status" key.
        const std::string base = ctx.base_url(); // ends with '/'
        Json o = Json::object();
        for (const char* svc : kEveServices) o[svc] = base + svc + "/";
        return Response::json(o.dump());
    });
}

} // namespace mc5
