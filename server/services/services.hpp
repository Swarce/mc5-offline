// Service wiring for the MC5 Offline Federation server.
//
// ServerContext holds the shared configuration and the in-memory account store.
// register_services() installs every route on the Router. Each service is in its
// own .cpp, matching the Gaia service split (eve, pandora, auth, ... ). For M0
// only the discovery + auth chain and a logging catch-all are implemented; the
// rest arrive in M1/M2.
//
// C++17.
#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include "../core/http.hpp"
#include "../core/sha1.hpp"

namespace mc5 {

// Deterministic account identity derived from a credential, so independent
// per-device servers agree on ids for later LAN/internet play (MCVS scheme).
inline std::string account_for(const std::string& credential) {
    return Sha1::hex(credential).substr(0, 24);
}

// A minimal account store. Tokens are self-describing ("<account>.<nonce>") so a
// future LAN host can tell which device issued a token. Persistence is M1; this
// is in-memory for the boot/dev-loop milestone.
class AccountStore {
public:
    // Returns the (stable) account id for a credential, creating it if unknown.
    std::string ensure(const std::string& credential) {
        std::lock_guard<std::mutex> g(mu_);
        auto it = by_credential_.find(credential);
        if (it != by_credential_.end()) return it->second;
        std::string account = account_for(credential);
        by_credential_[credential] = account;
        by_account_[account] = credential;
        return account;
    }
    bool credential_for(const std::string& account, std::string& out) const {
        std::lock_guard<std::mutex> g(mu_);
        auto it = by_account_.find(account);
        if (it == by_account_.end()) return false;
        out = it->second;
        return true;
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::string> by_credential_;
    std::unordered_map<std::string, std::string> by_account_;
};

struct ServerContext {
    std::string client_id = "1924:56128:6.0.12a:android:googleplay";
    std::string data_center = "mc5";
    std::string public_host = "127.0.0.1";
    int port = 51780;
    // Scheme we advertise in eve/urls and pandora/locate. Plain http for the
    // desktop dev loop; https for the embedded (loopback-TLS) build.
    std::string scheme = "http";

    AccountStore accounts;

    // Base URL we hand out, e.g. "http://127.0.0.1:51780/".
    std::string base_url() const {
        return scheme + "://" + public_host + ":" + std::to_string(port) + "/";
    }
};

// Installs all routes (core status routes + services + catch-all) on the router.
void register_services(Router& router, ServerContext& ctx);

// Individual service registrars (one per Gaia service).
void register_core(Router& router, ServerContext& ctx);
void register_eve(Router& router, ServerContext& ctx);
void register_pandora(Router& router, ServerContext& ctx);
void register_auth(Router& router, ServerContext& ctx);
void register_misc(Router& router, ServerContext& ctx); // catch-all logger

} // namespace mc5
