// eve: the environment switcher. The client's first call. It asks for the list of
// datacenters, picks the active+preferred one, then asks that datacenter for its
// service URLs, of which "pandora" (and "federation") are what matter.
//
// Shapes verified from the client's Java eve client (RemoteImageManager.GetDatacenter
// / GetEnvironment): datacenters is a JSON array of {name,status,preferred} and the
// client selects status=="active" && preferred==true; urls is an object read for its
// "pandora" field. Native Gaia additionally rewrites the "pandora"/"federation" URLs
// from http:// to https:// (00-recon.md 2.1) and reads both keys.

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

void register_eve(Router& router, ServerContext& ctx) {
    router.add("GET", "config/{clientId}/datacenters", [&ctx](const Request&) {
        Json arr = Json::array();
        Json dc = Json::object();
        dc["name"] = ctx.data_center;
        dc["status"] = "active";
        dc["preferred"] = true;
        arr.push_back(std::move(dc));
        return Response::json(arr.dump());
    });

    router.add("GET", "config/{clientId}/datacenters/{dc}/urls", [&ctx](const Request&) {
        // The client reads "pandora"; native Gaia also reads "federation". Point both
        // at our one host; pandora/locate then hands out per-service URLs.
        const std::string base = ctx.base_url();
        Json o = Json::object();
        o["pandora"] = base;
        o["federation"] = base;
        return Response::json(o.dump());
    });
}

} // namespace mc5
