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

// The credential the client is authorizing. The user-token builders send it as
// "username"; some paths use "credential". Fall back to a per-device anonymous id.
std::string requested_credential(const Request& req, const ServerContext& ctx) {
    std::string c = req.value("username");
    if (c.empty()) c = req.value("credential");
    if (c.empty()) {
        std::string dev = req.value("device_id");
        c = dev.empty() ? std::string("anon") : ("anon:" + dev);
    }
    return c;
}

Response authorize(ServerContext& ctx, const Request& req) {
    std::string credential = requested_credential(req, ctx);
    std::string account = ctx.accounts.ensure(credential);
    std::string scope = req.value("scope");

    Json o = Json::object();
    o["access_token"] = make_token(account);
    o["scope"] = scope; // echo requested scopes (empty is acceptable)
    logd("auth/authorize: credential=%s -> account=%s scope='%s'", credential.c_str(), account.c_str(), scope.c_str());
    return Response::json(o.dump());
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
    Json creds = Json::array();
    if (!credential.empty()) {
        Json c = Json::object();
        c["credential"] = credential;
        creds.push_back(std::move(c));
    }
    o["credentials"] = std::move(creds);
    return Response::json(o.dump());
}

} // namespace

void register_auth(Router& router, ServerContext& ctx) {
    router.add("POST", "authorize", [&ctx](const Request& r) { return authorize(ctx, r); });
    router.add("GET", "authorize", [&ctx](const Request& r) { return authorize(ctx, r); });

    router.add("GET", "users/me", [&ctx](const Request& r) { return users_me(ctx, r); });

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
