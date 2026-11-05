// asset (IRIS config provider): serves the Gaia "IRIS" config assets the native
// Restrictions/legislation + Behavioral managers download after login. Serving an
// empty "{}" made both managers fail validation (compliancy: missing
// "LegislationTypes" -> ParseConfigJson error 0x1c = login "compliancy error 28";
// GetLegislationVersion stays empty. NB: Reset 0x1394020 runs only after a SUCCESSFUL
// parse, and the client caches compliancy.json before validating it, so a bad reply
// poisons compliancy.bin permanently — diag.cpp deletes that cache at boot; behavioral:
// missing required version fields + rules array). We serve minimal VALID configs.
//
// Schemas reverse-engineered from libMC5 (Restrictions::ParseConfigJson FUN_0148d9f8
// / FUN_01490b98 etc.; BehavioralMgr validator FUN_0147a330). See
// docs/research/02-post-auth-chain.md.
//
//   compliancy.json: one legislation "RestOfTheWorld" that covers the player's
//     country; LegislationVersion < "20.0.0" so the conditional "StoreType" block is
//     skipped; no "<GameType>" section => empty restriction map => no age gate.
//     "StoreType":["google"] is also served (state 5 passes store "google"), so the
//     config still parses if the 0x1390e48("20.0.0", LegislationVersion) comparison
//     runs the other way and the StoreType block (0x1391350) is required.
//   behavioral.json: required version strings + an empty "rules" array => no rules.
//
// Any other asset (e.g. GameOptions) keeps the empty-object default via the catch-all.

#include "services.hpp"

#include "../core/http.hpp"

namespace mc5 {

namespace {

// The IRIS validator (libMC5 @0x1378bd0) requires version fields on every IRIS
// config: config_format_version, behavioral_version AND consent_version. With any
// missing it flags the config invalid; behavioral.json then fails BEFORE compliancy
// is even scheduled (so compliancy.json was never fetched and legislationVersion
// stayed empty -> Restrictions "restricted mode" -> the connection-error popup).
// So both configs carry all three version fields (harmless extras), and compliancy
// additionally carries a non-empty legislation that resolves to non-restricted.
//
// Countries are matched against the legislation list; an unlisted country falls back
// (non-fatally) to RestOfTheWorld, so this list only needs the common cases.
const char* kCompliancyJson =
    "{\"config_format_version\":\"1.0.0\",\"behavioral_version\":\"1.0.0\",\"consent_version\":\"1.0.0\","
    "\"LegislationVersion\":\"1.0.0\","
    "\"LegislationTypes\":[\"RestOfTheWorld\"],"
    "\"RestOfTheWorld\":[\"CA\",\"US\",\"GB\",\"FR\",\"DE\",\"BR\",\"AU\",\"IN\"],"
    "\"StoreType\":[\"google\"]}";

const char* kBehavioralJson =
    "{\"config_format_version\":\"1.0.0\",\"behavioral_version\":\"1.0.0\",\"consent_version\":\"1.0.0\","
    "\"rules\":[]}";

} // namespace

void register_asset(Router& router, ServerContext& /*ctx*/) {
    router.add("GET", "assets/{clientId}/compliancy.json",
               [](const Request&) { return Response::json(kCompliancyJson); });
    router.add("GET", "assets/{clientId}/behavioral.json",
               [](const Request&) { return Response::json(kBehavioralJson); });
}

} // namespace mc5
