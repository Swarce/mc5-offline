// config (CRM / live config): the native CRM + IAP init fetch a config document
// after auth (GET configs/users/me). It is parsed for store/IAP data and feature
// flags; a bare "{}" can leave the IAP callback or a flag reader unhappy, so we
// return a small but structurally-complete document that disables every blocking
// popup (no mandatory update, no age-gate, not under maintenance) and gives IAP an
// empty-but-present price list. Served for any token and any trailing selector,
// always 200 (never 403/404 — those wipe/abort on Gaia).
//
// Shape follows the MCVS CrmDocumentBuilder (docs/protocol/content.md): top-level
// flags + an "iap" object. Refined from the device log as the client reveals which
// keys it actually reads.

#include "services.hpp"

#include "../core/json.hpp"
#include "../core/log.hpp"

namespace mc5 {

namespace {

Response crm_document(ServerContext& ctx) {
    Json o = Json::object();
    // No blocking states.
    o["status"] = "none";
    o["maintenance"] = false;
    o["mandatory_update"] = false;
    o["optional_update"] = false;
    o["age_gate"] = false;
    o["is_development"] = false;
    // IAP: present but empty, so IapStoreComponent.InitNative's callback fires.
    Json iap = Json::object();
    iap["prices"] = Json::array();
    iap["products"] = Json::array();
    iap["enabled"] = false;
    o["iap"] = std::move(iap);
    // Common live-config buckets the client may index into; empty is fine.
    o["features"] = Json::object();
    o["events"] = Json::array();
    o["config"] = Json::object();
    return Response::json(o.dump());
}

} // namespace

void register_config(Router& router, ServerContext& ctx) {
    // The CRM document, by token identity, with or without a trailing selector.
    auto h = [&ctx](const Request&) { return crm_document(ctx); };
    router.add("GET", "configs/users/me", h);
    router.add("GET", "configs/users/me/{*selector}", h);
    router.add("GET", "configs/{*selector}", h);
}

} // namespace mc5
