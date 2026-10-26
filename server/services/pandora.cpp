// pandora: the service locator. Given a service name it returns that service's
// base URL. The client calls both forms: GET locate/{service} and
// GET locate?service=<name>. Our one host serves every service, so we hand back
// base_url + "<service>/"; relative request paths then land on the service routes
// registered at the root.
//
// The client treats the body as the service URL (the Java IRIS path prefixes a
// scheme if absent; MCVS returned a plain-text URL). We return the full URL as
// text/plain and refine from the device log if a caller expects JSON.

#include "services.hpp"

#include "../core/log.hpp"

namespace mc5 {

namespace {
Response locate(ServerContext& ctx, const std::string& service) {
    std::string svc = service;
    if (svc.empty()) svc = "config";
    std::string url = ctx.base_url() + svc + "/";
    return Response::text(url);
}
} // namespace

void register_pandora(Router& router, ServerContext& ctx) {
    router.add("GET", "locate/{service}", [&ctx](const Request& req) {
        return locate(ctx, req.param("service"));
    });
    // Query form: GET locate?service=<name>&client_id=...
    router.add("GET", "locate", [&ctx](const Request& req) {
        return locate(ctx, req.value("service"));
    });
}

} // namespace mc5
