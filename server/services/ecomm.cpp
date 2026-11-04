// ecomm / crm_iap: the Java ecomm SDK + native IAP init poll a few store endpoints
// after auth. They expect typed-but-empty results; a bare "{}"/"[]" guess from the
// catch-all can mis-shape the parse, so answer the known ones explicitly. All 200.
//   GET ecomm_api_root/android/banned_services/       -> [] (nothing disabled)
//   GET ecomm_api_root/purchases/?get_non_consumables -> {"non_consumables":[]}
//   GET crm_iap/subscriptions/?verify_subscription    -> {"subscriptions":[]}

#include "services.hpp"

#include "../core/http.hpp"

namespace mc5 {

void register_ecomm(Router& router, ServerContext& /*ctx*/) {
    router.add("GET", "android/banned_services", [](const Request&) {
        return Response::json("[]");
    });
    router.add("GET", "android/banned_services/{*rest}", [](const Request&) {
        return Response::json("[]");
    });
    router.add("GET", "purchases", [](const Request&) {
        return Response::json("{\"non_consumables\":[],\"consumables\":[]}");
    });
    router.add("GET", "purchases/{*rest}", [](const Request&) {
        return Response::json("{\"non_consumables\":[],\"consumables\":[]}");
    });
    router.add("GET", "subscriptions", [](const Request&) {
        return Response::json("{\"subscriptions\":[]}");
    });
    router.add("GET", "subscriptions/{*rest}", [](const Request&) {
        return Response::json("{\"subscriptions\":[]}");
    });
}

} // namespace mc5
