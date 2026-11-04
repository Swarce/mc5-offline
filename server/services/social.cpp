// social (Osiris): the player's social profile (nickname), friend connections and
// requests. On boot the client GETs accounts/me; if it has no name it assigns a
// default "SOLDIER_<n>" and POSTs accounts/me, then expects to read that name back.
// Serving "{}" (no persisted name) made the client regenerate a new random name and
// RESTART the whole online session every ~1s. We persist the profile in-memory and
// return it, and return real empty ARRAYS for connections/requests (the client
// iterates them). Shapes follow the MCVS Osiris contract (report 02 §S/SP):
//   GET  accounts/me                       -> {credential,name,account,groups:[]}
//   POST accounts/me (name,language,country)-> the updated profile
//   GET  accounts/{credential}             -> {credential,name,groups:[]}
//   GET  accounts/me/connections/{type}    -> []    (array of connections)
//   GET  accounts/me/requests[/sent]       -> []    (array of requests)

#include "services.hpp"

#include <map>
#include <mutex>
#include <string>

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {

struct SocialProfile {
    std::string name, language, country;
};

std::mutex g_mu;
std::map<std::string, SocialProfile> g_profiles; // account -> profile

std::string acct_from_token(const std::string& token) {
    std::size_t dot = token.find('.');
    return dot == std::string::npos ? token : token.substr(0, dot);
}

Json profile_json(const std::string& account, const SocialProfile& p) {
    Json o = Json::object();
    o["account"] = account;
    o["credential"] = std::string("fed_id:") + account;
    o["name"] = p.name;
    o["language"] = p.language.empty() ? std::string("en") : p.language;
    o["country"] = p.country.empty() ? std::string("US") : p.country;
    o["groups"] = Json::array();
    return o;
}

} // namespace

void register_social(Router& router, ServerContext& /*ctx*/) {
    // Read the caller's profile (name persisted from POST accounts/me).
    router.add("GET", "accounts/me", [](const Request& r) {
        std::string acct = acct_from_token(r.value("access_token"));
        std::lock_guard<std::mutex> g(g_mu);
        auto it = g_profiles.find(acct);
        SocialProfile p = it != g_profiles.end() ? it->second : SocialProfile{};
        return Response::json(profile_json(acct, p).dump());
    });
    // Create/update the profile; persist the name so the next GET returns it (ends
    // the "assign a new random SOLDIER_ name every cycle" loop).
    router.add("POST", "accounts/me", [](const Request& r) {
        std::string acct = acct_from_token(r.value("access_token"));
        std::lock_guard<std::mutex> g(g_mu);
        SocialProfile& p = g_profiles[acct];
        std::string name = r.value("name");
        if (!name.empty()) p.name = name;
        std::string lang = r.value("language");
        if (!lang.empty()) p.language = lang;
        std::string country = r.value("country");
        if (!country.empty()) p.country = country;
        logi("social: profile %s name='%s'", acct.c_str(), p.name.c_str());
        return Response::json(profile_json(acct, p).dump());
    });
    router.add("POST", "accounts/me/status_line", [](const Request&) { return Response::json("{}"); });

    // Connections and requests: real empty arrays (the client iterates them).
    router.add("GET", "accounts/me/connections/{type}/count", [](const Request&) { return Response::json("0"); });
    router.add("GET", "accounts/me/connections/{type}", [](const Request&) { return Response::json("[]"); });
    router.add("POST", "accounts/me/connections/{type}/import", [](const Request&) { return Response::json("{}"); });
    router.add("POST", "accounts/me/connections/{type}/{credential}/delete", [](const Request&) { return Response::json("{}"); });
    router.add("POST", "accounts/me/connections/{type}", [](const Request&) { return Response::json("{}"); });
    router.add("GET", "accounts/me/requests/sent", [](const Request&) { return Response::json("[]"); });
    router.add("POST", "accounts/me/requests/sent/{id}/cancel", [](const Request&) { return Response::json("{}"); });
    router.add("GET", "accounts/me/requests", [](const Request&) { return Response::json("[]"); });
    router.add("POST", "accounts/me/requests/{id}/{op}", [](const Request&) { return Response::json("{}"); });

    // Another player's social profile (by credential). Registered AFTER accounts/me
    // so the literal "me" wins over the {credential} capture.
    router.add("GET", "accounts/{credential}", [](const Request& r) {
        Json o = Json::object();
        o["credential"] = r.param("credential");
        o["name"] = "";
        o["groups"] = Json::array();
        return Response::json(o.dump());
    });
}

} // namespace mc5
