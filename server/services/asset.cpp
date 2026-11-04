// asset (IRIS config provider): serves the Gaia "IRIS" config assets the native
// Restrictions/legislation + Behavioral managers download after login. Serving an
// empty "{}" made both managers fail validation (compliancy: missing
// "LegislationTypes" -> ParseConfigJson error 0x1c -> Reset -> GetLegislationVersion
// = JSON_NOT_INITIALIZED; behavioral: missing required version fields + rules array),
// which tore down and relooped the whole online session every ~1s ("log-brazil :
// legislationVersion:" empty on device). We serve minimal VALID configs instead.
//
// Schemas reverse-engineered from libMC5 (Restrictions::ParseConfigJson FUN_0148d9f8
// / FUN_01490b98 etc.; BehavioralMgr validator FUN_0147a330). See
// docs/research/02-post-auth-chain.md.
//
//   compliancy.json: one legislation "RestOfTheWorld" that covers the player's
//     country; LegislationVersion < "20.0.0" so the conditional "StoreType" block is
//     skipped; no "<GameType>" section => empty restriction map => no age gate.
//   behavioral.json: required version strings + an empty "rules" array => no rules.
//
// Any other asset (e.g. GameOptions) keeps the empty-object default via the catch-all.

#include "services.hpp"

#include "../core/http.hpp"

namespace mc5 {

namespace {

// Countries are matched against this list; an unlisted country falls back
// (non-fatally) to RestOfTheWorld, so this list only needs the common cases.
const char* kCompliancyJson =
    "{\"LegislationVersion\":\"1.0.0\","
    "\"LegislationTypes\":[\"RestOfTheWorld\"],"
    "\"RestOfTheWorld\":[\"CA\",\"US\",\"GB\",\"FR\",\"DE\",\"BR\",\"AU\",\"IN\"]}";

const char* kBehavioralJson =
    "{\"config_format_version\":\"1.0.0\",\"behavioral_version\":\"1.0.0\",\"rules\":[]}";

} // namespace

void register_asset(Router& router, ServerContext& /*ctx*/) {
    router.add("GET", "assets/{clientId}/compliancy.json",
               [](const Request&) { return Response::json(kCompliancyJson); });
    router.add("GET", "assets/{clientId}/behavioral.json",
               [](const Request&) { return Response::json(kBehavioralJson); });
}

} // namespace mc5
