// eve: the environment switcher. The client's first call. It asks for the list of
// datacenters, picks the active+preferred one, then asks that datacenter for its
// service URLs.
//
// Shapes mirror the known-good MCVS Offline eve contract (same Gaia SDK), confirmed
// against this client on device (Nov 2026):
//
//   GET config/{clientId}/datacenters
//     -> [{"name":<dc>,"status":"active","preferred":true,"country_code":"US",
//          "_datacenter_id":<dc>}]
//        The client takes the first entry with preferred=true; the name must be
//        non-empty ("Incorrect datacenter" otherwise).
//        The native Gaia DataCenter parser (libMC5 0xca8ed8) REQUIRES the string
//        fields name, status, _datacenter_id and the bool preferred (country_code is
//        optional); a missing _datacenter_id returns -24, the login FSM's
//        "dataCenter" re-check (0xbcf430 -> callback 0xbd1518) then sets the login
//        error "glrer_<type>_<code>_<msg>" and the game shows "Failed to connect!"
//        (every 3rd time "Servers are temporarily overloaded" — same failure, a
//        retry counter picks the text). See docs/research/02-post-auth-chain.md §13.
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
// The native pandora-discovery parser reads the urls object into a fixed ~1 KB
// buffer and fails (connection-error 0x1d) if it overruns — the 8-key response
// (405 B) was enough to break it while the small datacenters array parsed fine.
// So keep this to the minimum login needs: "pandora" (service discovery) and
// "ecomm_api_root"/"crm_iap" (IAP init throws without them); "federation" too.
// Everything else (auth, storage, game_portal, …) is located via pandora/locate.
const char* kEveServices[] = {
    "pandora", "federation", "ecomm_api_root", "crm_iap",
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
        dc["_datacenter_id"] = ctx.data_center;
        arr.push_back(std::move(dc));
        return Response::json(arr.dump());
    });

    router.add("GET", "config/{clientId}/datacenters/{dc}/urls", [&ctx](const Request&) {
        // One object of service -> "<base><service>/", plus an explicit
        // "status":"none". The native Gaia config parses a status/code field into a
        // ConfigStatus; "none" is the only value that shows no update/maintenance
        // popup (any other string throws), and MCVS's known-good eve contract
        // returns it explicitly rather than omitting it.
        const std::string base = ctx.base_url(); // ends with '/'
        Json o = Json::object();
        o["status"] = "none";
        for (const char* svc : kEveServices) o[svc] = base + svc + "/";
        return Response::json(o.dump());
    });
}

} // namespace mc5
