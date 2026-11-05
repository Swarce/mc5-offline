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
//     -> {"status":"none","pandora":...,"federation":...,"ecomm_api_root":...,
//         "crm_iap":...,"game_portal":...}
//        A JSON object of service -> URL. "status":"none" is the only status that
//        shows no update/maintenance popup. pandora is required for every fed
//        service; ecomm_api_root and crm_iap are located by IapStoreComponent
//        .InitNative, which THROWS without them. Answered for any dc name.
//
//        game_portal: read straight from this object (not via pandora) by the Anubis
//        manager's Start 0xc07020 (eve lookup 0xc86e18, must be a non-empty JSON
//        string). Without it Start returns 0, nothing connects, and login state 8
//        fails with the bare code "gl". The client never uses it as an HTTP base or
//        TCP target — it only forwards it (https->http, plus
//        "/%d/190/private/OfficialScripts/mc5Portal.wsgi") to the TS inside
//        ClientSendInitSettings — so no trailing slash.
//        federation: its presence as a string selects Anubis mode 0 (POST
//        <federation>/sessions/..., see matchmaker.cpp); without it the client takes
//        mode 1, which needs a Gaia nonce exchange we have not mapped. Keep it.
//        See docs/research/02-post-auth-chain.md §15.

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {
// Keep this to what login needs: "pandora" (service discovery), "ecomm_api_root"/
// "crm_iap" (IAP init throws without them) and "federation" (selects Anubis mode 0);
// "game_portal" is added separately (no trailing slash). Everything else (auth,
// storage, matchmaker, …) is located via pandora/locate. (An older note blamed a
// "~1 KB parse buffer" for an eve failure; that was refuted — 02 §14.B.)
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
        o["game_portal"] = base + "game_portal"; // no trailing slash (client appends a path)
        return Response::json(o.dump());
    });
}

} // namespace mc5
