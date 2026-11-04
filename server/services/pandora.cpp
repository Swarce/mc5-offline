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
// The IRIS config provider (FUN_01486a28) runs the pandora/locate RESPONSE through
// the native URL normaliser FUN_01488b50, which prepends a scheme based on the port
// (443->https, 80->http, any-other-port->http) and expects a SCHEME-LESS host:port.
// If we hand it a scheme-prefixed URL it finds the first ':' inside the scheme and
// mangles it, e.g. "https://127.0.0.1:51780/asset/" -> "http://https://127.0.0.1:...",
// whose host "https" fails to resolve ("IRIS download failed: HTTP 0", observed on
// device). So the asset URL must be scheme-less; the normaliser then yields
// "http://127.0.0.1:51780/asset/", which our loopback listener serves. The fed
// services (auth/alert/message/...) consume the locate response DIRECTLY (no
// normaliser), so they must keep an explicit scheme — only asset needs this.
bool iris_normalized(const std::string& svc) { return svc == "asset"; }

Response locate(ServerContext& ctx, const std::string& service) {
    std::string svc = service;
    if (svc.empty()) svc = "config";
    std::string url;
    if (iris_normalized(svc))
        url = ctx.public_host + ":" + std::to_string(ctx.port) + "/" + svc + "/"; // scheme-less
    else
        url = ctx.base_url() + svc + "/"; // explicit scheme (base_url ends with '/')
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
