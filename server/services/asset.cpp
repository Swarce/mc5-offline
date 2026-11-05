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
// docs/research/02-post-auth-chain.md §14 and §17.
//
//   compliancy.json: one legislation "RestOfTheWorld" that covers the player's
//     country; LegislationVersion < "20.0.0" so the conditional "StoreType" block is
//     skipped. "StoreType":["google"] is also served (state 5 passes store "google").
//
//     The <GameType> section is REQUIRED (§17). The first-run age/gender screen asks
//     Restrictions for this player's restrictions (0xc1c4e0 -> 0x13cfc68). The local
//     evaluator 0x13919d0 refuses an EMPTY restriction map (0x13919fc cbz -> "invalid
//     json!", 0x1c), and the map is only filled by 0x1391558 from
//     json[<gameTypeName>][<legislation>]. With no section the result was always 0x1c
//     -> age callback ok=0/connFail=1 -> the "ageLimit" popup, UI string 1733 "Failed
//     to connect! Please check your Internet connection" -> closing it re-opened the
//     age screen (+ Didomi notice): the pre-tutorial "connection error" loop.
//     Game type is the constant 2 (0xbcdd2c) = "Adult_Games_ads_on" (name table
//     0x1391490); the other four names are served too in case the type differs. The
//     legislation key is the matched LegislationTypes entry or the fallback "RotW".
//     Each holds ONE member "none" whose value is an EMPTY array: any member name is
//     inserted (unknown name -> restriction id 0x58 via 0x1395038) with an empty
//     condition list, which every evaluator handler ignores -> result 0, no
//     restrictions. NEVER "[{}]": 0x1392088 adds the restriction unconditionally for
//     an empty condition object. NEVER name a member after a blocking restriction.
//   behavioral.json: required version strings + an empty "rules" array => no rules.
//
// Every other asset (GameOptions, use_custom_param, the events/videos atlas packs and
// their metadata/hash) answers 404 with no body: the client's clean "asset absent"
// path (bundled GameOptions kept; use_custom_param's stale ETag/local copy dropped;
// the atlas manager parks the slot). Serving "{}" made the client cache "{}" as
// atlas.dat/atlas2.dat (decoded as banner textures) and as use_custom_param. 404 is
// never retried; 5xx/408 would be retried with backoff and 204 counts as an error.

#include "services.hpp"

#include "../core/http.hpp"
#include "../core/log.hpp"

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
    "\"StoreType\":[\"google\"],"
    "\"Adult_Games_ads_on\":{\"RestOfTheWorld\":{\"none\":[]},\"RotW\":{\"none\":[]}},"
    "\"Adult_Games_ads_off\":{\"RestOfTheWorld\":{\"none\":[]},\"RotW\":{\"none\":[]}},"
    "\"Mixt_Standard\":{\"RestOfTheWorld\":{\"none\":[]},\"RotW\":{\"none\":[]}},"
    "\"Mixt_Plus\":{\"RestOfTheWorld\":{\"none\":[]},\"RotW\":{\"none\":[]}},"
    "\"Kids\":{\"RestOfTheWorld\":{\"none\":[]},\"RotW\":{\"none\":[]}}}";

const char* kBehavioralJson =
    "{\"config_format_version\":\"1.0.0\",\"behavioral_version\":\"1.0.0\",\"consent_version\":\"1.0.0\","
    "\"rules\":[]}";

} // namespace

static Response asset_absent(const Request& req) {
    logi("asset: %s '%s' -> 404 (absent; client keeps its bundled/default copy)",
         req.method.c_str(), req.param("name").c_str());
    Response r = Response::json("", 404);
    r.content_type = "text/plain";
    return r;
}

void register_asset(Router& router, ServerContext& /*ctx*/) {
    router.add("GET", "assets/{clientId}/compliancy.json",
               [](const Request&) { return Response::json(kCompliancyJson); });
    router.add("GET", "assets/{clientId}/behavioral.json",
               [](const Request&) { return Response::json(kBehavioralJson); });
    // Registered AFTER the two configs (first match wins): everything else is absent.
    // Method "*" covers the HEAD probes (server.cpp sends no body for HEAD).
    router.add("*", "assets/{clientId}/{name}", asset_absent);
    router.add("*", "assets/{clientId}/{name}/metadata", asset_absent);
    router.add("*", "assets/{clientId}/{name}/metadata/hash", asset_absent);
}

} // namespace mc5
