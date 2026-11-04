#include "services.hpp"

namespace mc5 {

void register_services(Router& router, ServerContext& ctx) {
    // Service names that may arrive as a leading path segment, because the URLs we
    // hand out (eve's urls object and pandora/locate) are "<base><service>/": a
    // request can come in as "/auth/authorize" or "/pandora/locate/auth" (string
    // concat) as well as the root form (RFC-3986 relative resolution drops the
    // service segment). Any such prefix is stripped so the root route matches.
    // Includes the eve-served services (pandora itself, ecomm_api_root, crm_iap …)
    // and the native-only ones, not just the pandora-located fed services.
    router.set_service_prefixes({
        // fed services (located via pandora)
        "auth", "storage", "message", "feeds", "leaderboard", "social", "asset",
        "matchmaker", "lobby", "lottery", "voice", "config", "alert", "schedule",
        "transaction", "groupchat", "game_stats", "crm", "assets",
        // eve-served services (eve urls object)
        "pandora", "federation", "game_portal", "ads_agency", "marketing_site",
        "ecomm_api_root", "crm_iap", "etsv2",
        // native-only services
        "globalidservice",
    });

    // Order: specific service routes first, catch-all fallback last.
    register_core(router, ctx);
    register_eve(router, ctx);
    register_pandora(router, ctx);
    register_auth(router, ctx);
    register_config(router, ctx);
    register_ecomm(router, ctx);
    register_matchmaker(router, ctx);
    register_asset(router, ctx);
    register_social(router, ctx);
    register_alert(router, ctx);
    register_misc(router, ctx); // installs the fallback
}

} // namespace mc5
