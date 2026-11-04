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
// Non-fed services the client reads straight from eve's urls object; fed services
// are located via pandora. This matches the known-good MCVS eve contract. (A full
// superset was tried and regressed the native parse, so keep it to the non-fed
// set.) "federation" is kept too: native Gaia reads it alongside "pandora".
const char* kEveServices[] = {
    "pandora", "federation", "game_portal", "ads_agency",
    "marketing_site", "ecomm_api_root", "crm_iap", "etsv2",
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
