// auth (Janus): OAuth-like token issuing. authorize auto-creates an account for an
// unknown (anonymous) credential and returns {access_token, scope}; users/me returns
// the account + credentials for a token; encrypt_token/verify back the Anubis login.
//
// Rules from 00-recon/Phase 1b and the MCVS protocol: tokens never expire, auth
// failures are 401 (never 403), scopes are echoed. Tokens are self-describing
// ("<account>.<nonce>") so a LAN host can later tell which device issued one.

#include "services.hpp"

#include <atomic>

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {

std::atomic<unsigned long long> g_nonce{1};

std::string make_token(const std::string& account) {
    unsigned long long n = g_nonce.fetch_add(1);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", n);
    return account + "." + buf;
}

std::string account_from_token(const std::string& token) {
    std::size_t dot = token.find('.');
    return dot == std::string::npos ? std::string() : token.substr(0, dot);
}

// The credential the client is authorizing, normalized to ONE canonical
// "type:username" form so every auth path derives the SAME account id. The
// tracking/BI session sends a single combined field credential=anonymous:<GLUID>,
// while the main game session (builder FUN_00d18d80) sends SEPARATE accountType +
// username fields. Reading "username" first (as before) made those two derive
// different accounts and desynced users/me/verify/the TS. Compose consistently:
// prefer the already-combined "credential", else join accountType/credential_type
// with username.
std::string requested_credential(const Request& req, const ServerContext& ctx) {
    std::string cred = req.value("credential");
    if (!cred.empty()) return cred; // already "type:username" (tracking path)

    std::string user = req.value("username");
    if (!user.empty()) {
        std::string type = req.value("credential_type");
        if (type.empty()) type = req.value("accountType");
        if (!type.empty() && user.find(':') == std::string::npos) return type + ":" + user;
        return user;
    }
    std::string dev = req.value("device_id");
    return dev.empty() ? std::string("anon") : ("anon:" + dev);
}

Response authorize(ServerContext& ctx, const Request& req) {
    std::string credential = requested_credential(req, ctx);
    std::string account = ctx.accounts.ensure(credential);
    std::string scope = req.value("scope");

    Json o = Json::object();
    o["access_token"] = make_token(account);
    o["scope"] = scope;              // echo requested scopes verbatim (empty is acceptable)
    o["token_type"] = "bearer";      // native Gaia may read these; harmless to the proven path
    o["expires_in"] = 31536000;      // ~1 year; tokens never actually expire here
    logi("auth/authorize: credential=%s -> account=%s scope='%s'", credential.c_str(), account.c_str(), scope.c_str());
    return Response::json(o.dump());
}

// A stable 9-digit alias ("friend code") derived from the account id.
std::string alias_for(const std::string& account) {
    unsigned long long h = 1469598103934665603ULL; // FNV-1a over the account hex
    for (char c : account) { h ^= static_cast<unsigned char>(c); h *= 1099511628211ULL; }
    unsigned long long n = (h % 900000000ULL) + 100000000ULL; // 9 digits, no leading zero
    return std::to_string(n);
}

Response users_me(ServerContext& ctx, const Request& req) {
    std::string token = req.value("access_token");
    std::string account = account_from_token(token);
    if (account.empty()) {
        // No/!parseable token: 401, never 403 (403 wipes the profile).
        return Response::json("{\"error\":\"unauthorized\"}", 401);
    }
    std::string credential;
    ctx.accounts.credential_for(account, credential);

    Json o = Json::object();
    o["account"] = account;
    // credentials: an array of "type:username" STRINGS (not objects), matching the
    // native parser (and MCVS). account must not contain ':'.
    Json creds = Json::array();
    if (!credential.empty()) creds.push_back(Json(credential));
    o["credentials"] = std::move(creds);
    o["client_id"] = ctx.client_id;
    return Response::json(o.dump());
}

} // namespace

void register_auth(Router& router, ServerContext& ctx) {
    router.add("POST", "authorize", [&ctx](const Request& r) { return authorize(ctx, r); });
    router.add("GET", "authorize", [&ctx](const Request& r) { return authorize(ctx, r); });

    router.add("GET", "users/me", [&ctx](const Request& r) { return users_me(ctx, r); });

    // games/{game}/alias: the client assigns itself a 9-digit alias ("friend code")
    // on first run and reads it back. Uncaught (no popup) but must return {"alias":...}.
    auto alias_h = [&ctx](const Request& r) {
        std::string account = account_from_token(r.value("access_token"));
        if (account.empty()) account = ctx.client_id; // best-effort; alias is cosmetic
        Json o = Json::object();
        o["alias"] = alias_for(account);
        return Response::json(o.dump());
    };
    router.add("POST", "games/{game}/alias", alias_h);
    router.add("GET", "games/{game}/alias", alias_h);
    router.add("GET", "games/{game}/alias/{cred}", alias_h);

    // encrypt_token: returns the (encrypted) token for a nonce. We return the token
    // unchanged as plain text; the Anubis login forwards it to verify.
    router.add("GET", "encrypt_token", [](const Request& r) {
        return Response::text(r.value("access_token"));
    });
    router.add("POST", "encrypt_token", [](const Request& r) {
        return Response::text(r.value("access_token"));
    });

    // verify: confirm a token and report its account/credential. Used by the Anubis
    // controller on login (and by LAN hosts later).
    router.add("POST", "verify", [&ctx](const Request& r) {
        std::string token = r.value("access_token");
        if (token.empty()) token = r.value("token");
        std::string account = account_from_token(token);
        if (account.empty()) return Response::json("{\"error\":\"unauthorized\"}", 401);
        std::string credential;
        ctx.accounts.credential_for(account, credential);
        Json o = Json::object();
        o["account"] = account;
        o["credential"] = credential;
        o["client_id"] = ctx.client_id;
        return Response::json(o.dump());
    });
    router.add("GET", "verify", [&ctx](const Request& r) {
        std::string account = account_from_token(r.value("access_token"));
        if (account.empty()) return Response::json("{\"error\":\"unauthorized\"}", 401);
        Json o = Json::object();
        o["account"] = account;
        o["client_id"] = ctx.client_id;
        return Response::json(o.dump());
    });
}

} // namespace mc5
